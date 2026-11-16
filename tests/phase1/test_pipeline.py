import json
import tempfile
import unittest
from pathlib import Path

from scripts.phase1.cape_parser import iter_report_events
from scripts.phase1.event_normalizer import enrich_event
from scripts.phase1.handle_tracker import HandleTracker
from scripts.phase1.storage import read_jsonl, write_jsonl
from scripts.phase1.stream_reconstructor import reconstruct
from scripts.phase1.models import Event


def report(processes):
    return {"behavior": {"processes": processes}}


def synthetic_event(api, position, process_id, arguments, status=True, return_value="0x00000000"):
    event = enrich_event(
        Event(
            sample_id="sample",
            class_label="benign",
            report_path="benign/sample/report.json",
            source_process_index=0,
            process_call_position=position,
            process_id=str(process_id),
            parent_process_id=None,
            process_name=None,
            module_path=None,
            call_id_raw=position,
            timestamp_raw=None,
            api_raw=api,
            api_normalized=api.lower(),
            category_raw=None,
            thread_id_raw=None,
            status_raw=status,
            return_raw=return_value,
            repeated_raw=None,
            arguments_raw=arguments,
            arguments_normalized={k: [{"value": v}] for k, v in arguments.items()},
            operation_kind="unknown",
        )
    )
    return event


class Phase1Tests(unittest.TestCase):
    def make_report(self, payload):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "report.json"
        path.write_text(json.dumps(report(payload)), encoding="utf-8")
        return directory, path

    def test_primary_order_and_nested_arguments_roundtrip(self):
        holder, path = self.make_report(
            [
                {
                    "process_id": 10,
                    "parent_id": 1,
                    "calls": [
                        {
                            "id": 2,
                            "timestamp": "2024-01-01 00:00:00,002",
                            "api": "NtWriteFile",
                            "arguments": [
                                {"name": "FileHandle", "value": "0x10", "pretty_value": "handle"},
                                {"name": "Nested", "value": {"x": [1, 2]}},
                            ],
                        },
                        {
                            "id": 1,
                            "timestamp": "2024-01-01 00:00:00,001",
                            "api": "NtCreateFile",
                            "arguments": {"FileHandle": "0x10", "FileName": "C:\\a"},
                        },
                    ],
                }
            ]
        )
        try:
            events = list(iter_report_events(path, "sample", "benign", "benign/sample/report.json"))
            primary, merged, _ = reconstruct(events)
            self.assertEqual([e.process_call_position for e in primary], [0, 1])
            self.assertEqual([e.process_call_position for e in merged], [1, 0])
            self.assertEqual(primary[0].arguments_raw[1]["value"], {"x": [1, 2]})
        finally:
            holder.cleanup()

    def test_handle_creation_close_reuse_and_process_separation(self):
        def event(api, pos, pid, args):
            raw = {
                "sample_id": "s",
                "class_label": "ransomware",
                "report_path": "r/report.json",
                "source_process_index": 0,
                "process_call_position": pos,
                "process_id": str(pid),
                "parent_process_id": None,
                "process_name": None,
                "module_path": None,
                "call_id_raw": pos,
                "timestamp_raw": None,
                "api_raw": api,
                "api_normalized": api.lower(),
                "category_raw": None,
                "thread_id_raw": None,
                "status_raw": True,
                "return_raw": "0x00000000",
                "repeated_raw": None,
                "arguments_raw": args,
                "arguments_normalized": {k: [{"value": v}] for k, v in args.items()},
                "operation_kind": "unknown",
            }
            from scripts.phase1.models import Event
            return enrich_event(Event(**raw))

        tracker = HandleTracker()
        events = [
            event("NtCreateFile", 0, 1, {"FileHandle": "0x1", "FileName": "C:\\a"}),
            event("NtClose", 1, 1, {"Handle": "0x1"}),
            event("NtCreateFile", 2, 1, {"FileHandle": "0x1", "FileName": "C:\\b"}),
            event("NtWriteFile", 3, 1, {"FileHandle": "0x1"}),
            event("NtCreateFile", 0, 2, {"FileHandle": "0x1", "FileName": "C:\\c"}),
        ]
        for item in events:
            tracker.observe(item)
        self.assertEqual(tracker.counts["handle_generations"], 3)
        self.assertEqual(tracker.counts["candidate_reuse_after_close"], 1)
        self.assertEqual(tracker.counts["post_close_reference"], 0)
        self.assertEqual(len({o["candidate_key"] for e in events for o in e.handle_observations if o.get("candidate_key")}), 3)

    def test_missing_and_malformed_arguments_are_safe(self):
        holder, path = self.make_report([{"process_id": 1, "calls": [{"api": "NtClose", "arguments": None}, "bad"]}])
        try:
            events = list(iter_report_events(path, "sample", "benign", "benign/sample/report.json"))
            self.assertEqual(len(events), 1)
            enrich_event(events[0])
            self.assertEqual(events[0].handle_observations, [])
        finally:
            holder.cleanup()

    def test_jsonl_serialization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            records = [{"arguments_raw": [{"name": "x", "value": {"nested": [1]}}]}]
            self.assertEqual(write_jsonl(path, records), 1)
            self.assertEqual(list(read_jsonl(path)), records)

    def test_multiple_handles_one_path_and_conflicting_paths(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtCreateFile", 0, 1, {"FileHandle": "0x1", "FileName": "C:\\same"}),
            synthetic_event("NtCreateFile", 1, 1, {"FileHandle": "0x2", "FileName": "C:\\same"}),
            synthetic_event("NtWriteFile", 2, 1, {"FileHandle": "0x1", "FileName": "C:\\other"}),
        ]
        for event in events:
            tracker.observe(event)
        keys = {
            observation["candidate_key"]
            for event in events
            for observation in event.handle_observations
            if observation.get("candidate_key")
        }
        self.assertEqual(len(keys), 2)
        self.assertEqual(events[2].path_observations[0]["raw_value"], "C:\\other")

    def test_missing_close_and_repeated_writes_do_not_create_identities(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtCreateFile", 0, 1, {"FileHandle": "0x1", "FileName": "C:\\same"}),
            synthetic_event("NtWriteFile", 1, 1, {"FileHandle": "0x1"}),
            synthetic_event("NtWriteFile", 2, 1, {"FileHandle": "0x1"}),
        ]
        for event in events:
            tracker.observe(event)
        self.assertEqual(tracker.counts["handle_generations"], 1)
        self.assertEqual(len({o["candidate_key"] for e in events for o in e.handle_observations}), 1)

    def test_cross_process_collision_is_separate(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtCreateFile", 0, 1, {"FileHandle": "0x1", "FileName": "C:\\one"}),
            synthetic_event("NtCreateFile", 0, 2, {"FileHandle": "0x1", "FileName": "C:\\two"}),
        ]
        for event in events:
            tracker.observe(event)
        keys = [e.handle_observations[0]["candidate_key"] for e in events]
        self.assertNotEqual(keys[0], keys[1])

    def test_missing_arguments_are_unresolved_not_confirmed(self):
        tracker = HandleTracker()
        event = synthetic_event("NtWriteFile", 0, 1, {})
        tracker.observe(event)
        self.assertEqual(event.file_identity_candidates, [])
        self.assertEqual(event.handle_observations, [])

    def test_non_file_handles_are_preserved_without_identity_candidates(self):
        tracker = HandleTracker()
        event = synthetic_event(
            "NtProtectVirtualMemory",
            0,
            1,
            {"ProcessHandle": "0x1"},
        )
        tracker.observe(event)
        self.assertEqual(event.handle_observations[0]["object_type"], "non_file_or_unknown")
        self.assertEqual(event.file_identity_candidates, [])
        self.assertEqual(tracker.counts["handle_generations"], 0)

    def test_close_without_established_file_generation_is_uncertain(self):
        tracker = HandleTracker()
        event = synthetic_event("NtClose", 0, 1, {"Handle": "0x1"})
        tracker.observe(event)
        self.assertEqual(event.handle_observations[0]["object_type"], "uncertain")
        self.assertEqual(event.file_identity_candidates, [])
        self.assertEqual(tracker.counts["close_without_create"], 1)

    def test_repeated_close_and_post_close_reference_are_distinct_observations(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtCreateFile", 0, 1, {"FileHandle": "0x1"}),
            synthetic_event("NtClose", 1, 1, {"Handle": "0x1"}),
            synthetic_event("NtClose", 2, 1, {"Handle": "0x1"}),
            synthetic_event("NtWriteFile", 3, 1, {"FileHandle": "0x1"}),
        ]
        for event in events:
            tracker.observe(event)
        self.assertEqual(tracker.counts["post_close_reference"], 1)
        self.assertTrue(
            any(item["reason"] == "operation_after_candidate_close"
                for item in tracker.ambiguities)
        )

    def test_successful_create_write_close_establishes_candidate(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtCreateFile", 0, 1, {"FileHandle": "0x1", "FileName": "C:\\a"}),
            synthetic_event("NtWriteFile", 1, 1, {"FileHandle": "0x1"}),
            synthetic_event("NtClose", 2, 1, {"Handle": "0x1"}),
        ]
        for event in events:
            tracker.observe(event)
        self.assertEqual(tracker.counts["successful_create_open_generations"], 1)
        self.assertEqual(tracker.counts["operation_first_generations"], 0)
        self.assertTrue(events[1].file_identity_candidates)
        self.assertTrue(events[2].file_identity_candidates)

    def test_failed_create_does_not_seed_following_operation(self):
        tracker = HandleTracker()
        failed = synthetic_event(
            "NtCreateFile", 0, 1,
            {"FileHandle": "0x7ffee2e65db8", "FileName": "C:\\missing"},
            status=False,
            return_value="0xffffffffc0000034",
        )
        operation = synthetic_event("NtWriteFile", 1, 1, {"FileHandle": "0x7ffee2e65db8"})
        for event in (failed, operation):
            tracker.observe(event)
        self.assertEqual(tracker.counts["failed_create_open_observations"], 1)
        self.assertEqual(tracker.counts["successful_create_open_generations"], 0)
        self.assertEqual(tracker.counts["operation_first_generations"], 1)
        self.assertNotEqual(
            failed.handle_observations[0].get("candidate_key"),
            operation.handle_observations[0].get("candidate_key"),
        )

    def test_successful_open_and_failed_open_are_status_aware(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtOpenFile", 0, 1, {"FileHandle": "0x2", "FileName": "C:\\a"}),
            synthetic_event("NtClose", 1, 1, {"Handle": "0x2"}),
            synthetic_event(
                "NtOpenFile", 2, 1,
                {"FileHandle": "0x7ffe0000003d", "FileName": "C:\\b"},
                status=False,
                return_value="0xffffffffc000003a",
            ),
        ]
        for event in events:
            tracker.observe(event)
        self.assertEqual(tracker.counts["successful_create_open_generations"], 1)
        self.assertEqual(tracker.counts["failed_create_open_observations"], 1)
        self.assertIsNone(events[2].handle_observations[0].get("candidate_key"))

    def test_missing_status_and_return_are_unknown_not_success(self):
        tracker = HandleTracker()
        event = synthetic_event(
            "NtCreateFile", 0, 1, {"FileHandle": "0x3"}, status=None, return_value=None
        )
        tracker.observe(event)
        self.assertEqual(tracker.counts["unknown_create_open_observations"], 1)
        self.assertEqual(tracker.counts["successful_create_open_generations"], 0)
        self.assertIsNone(event.handle_observations[0].get("candidate_key"))

    def test_operation_first_then_successful_create_stays_separate(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtWriteFile", 0, 1, {"FileHandle": "0x4"}),
            synthetic_event("NtCreateFile", 1, 1, {"FileHandle": "0x4", "FileName": "C:\\a"}),
        ]
        for event in events:
            tracker.observe(event)
        keys = [
            event.handle_observations[0].get("candidate_key")
            for event in events
        ]
        self.assertNotEqual(keys[0], keys[1])
        self.assertEqual(tracker.counts["operation_first_generations"], 1)
        self.assertEqual(tracker.counts["successful_create_open_generations"], 1)

    def test_failed_create_invalidates_active_generation_for_next_operation(self):
        tracker = HandleTracker()
        events = [
            synthetic_event("NtCreateFile", 0, 1, {"FileHandle": "0x5"}),
            synthetic_event(
                "NtCreateFile",
                1,
                1,
                {"FileHandle": "0x5"},
                status=False,
                return_value="0xffffffffc0000034",
            ),
            synthetic_event("NtWriteFile", 2, 1, {"FileHandle": "0x5"}),
        ]
        for event in events:
            tracker.observe(event)
        self.assertIsNone(events[1].handle_observations[0].get("candidate_key"))
        self.assertNotEqual(
            events[0].handle_observations[0].get("candidate_key"),
            events[2].handle_observations[0].get("candidate_key"),
        )
        self.assertTrue(
            any(
                item["reason"]
                == "failed_create_open_conflicts_with_current_generation"
                for item in tracker.ambiguities
            )
        )

    def test_missing_process_id_uses_distinct_fallback_and_warning(self):
        holder, path = self.make_report(
            [
                {"calls": [{"api": "NtWriteFile", "arguments": {"FileHandle": "0x1"}}]},
                {"calls": [{"api": "NtWriteFile", "arguments": {"FileHandle": "0x1"}}]},
            ]
        )
        try:
            events = list(
                iter_report_events(path, "sample", "benign", "benign/sample/report.json")
            )
            self.assertEqual(events[0].process_id, "missing-process-0")
            self.assertEqual(events[1].process_id, "missing-process-1")
            self.assertEqual(events[0].warnings, ["missing_process_id"])
        finally:
            holder.cleanup()


if __name__ == "__main__":
    unittest.main()

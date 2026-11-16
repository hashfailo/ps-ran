import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from src.detection.bag_of_apis import BagOfAPIsModel, IncrementalBagOfAPIs
from src.detection.inference import load_saved_model


class DetectorTests(unittest.TestCase):
    def make_model(self, directory: Path) -> BagOfAPIsModel:
        model = BagOfAPIsModel(
            ["ntcreatefile", "ntwritefile", "ntclose"],
            {
                "benign": [-0.1, -2.0, -0.2],
                "ransomware": [-2.0, -0.1, -0.2],
            },
            {"benign": -0.7, "ransomware": -0.7},
            0.5,
            {"model_version": "test"},
        )
        model.save(directory)
        return model

    def test_save_load_and_incremental_prediction_are_consistent(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = self.make_model(directory)
            loaded = load_saved_model(directory)
            first = IncrementalBagOfAPIs(original).update("NtWriteFile", 0)
            second = IncrementalBagOfAPIs(loaded).update("NtWriteFile", 0)
            self.assertEqual(first, second)
            self.assertEqual(loaded.vocabulary, original.vocabulary)

    def test_first_alert_is_recorded_once(self):
        with tempfile.TemporaryDirectory() as temp:
            model = self.make_model(Path(temp))
            predictor = IncrementalBagOfAPIs(model)
            predictor.update("NtCreateFile", 0)
            result = predictor.update("NtWriteFile", 1)
            self.assertTrue(result["alert"])
            self.assertEqual(predictor.first_alert["event_position"], 1)
            predictor.update("NtWriteFile", 2)
            self.assertEqual(predictor.first_alert["event_position"], 1)

    def test_unknown_api_is_retained_as_an_event_without_vocabulary_hit(self):
        with tempfile.TemporaryDirectory() as temp:
            model = self.make_model(Path(temp))
            result = IncrementalBagOfAPIs(model).update("NtUnmappedApi", 3)
            self.assertFalse(result["vocabulary_hit"])
            self.assertEqual(result["events_seen"], 1)


if __name__ == "__main__":
    unittest.main()

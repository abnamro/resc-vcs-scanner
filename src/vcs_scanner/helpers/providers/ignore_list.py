# pylint: disable=E1101
# Standard Library
import csv
import logging
from datetime import UTC, datetime

# Third Party

logger = logging.getLogger(__name__)


class IgnoredListProvider:  # pylint: disable=R0902
    def __init__(self, ignore_findings_path: str | None):
        self.ignore_findings_path: str | None = ignore_findings_path
        self.today: datetime = datetime.now(UTC)

    def get_ignore_list(self) -> dict[str, True]:
        """
        Get the dictionary of ignored findings according to the file
        The output will contain a dictionary with the path|rule|line as key and True as value.
        We use a dictionary for random access instead of list.
        """
        if self.ignore_findings_path is None:
            return {}

        ignored = {}

        try:
            # read dsv: `path|rule_name|line_number|expiry_date`
            with open(self.ignore_findings_path, encoding="utf-8") as ignore_findings_file:
                csv_ignore_list = csv.reader(ignore_findings_file, delimiter="|")
                for row in csv_ignore_list:
                    if self._is_row_comment(row):
                        continue

                    if not self._is_row_valid(row):
                        continue

                    if not self._is_row_active(row):
                        continue

                    # we use the path, rule_name, line_number as a dictionary key
                    path = row[0]
                    rule = row[1]
                    line = row[2]
                    ignored[f"{path}|{rule}|{line}"] = True
        except FileNotFoundError:  # <- File does not exists: we just fail silently
            logger.warning(f"could not find {self.ignore_findings_path}")
            return {}

        return ignored

    def _is_row_comment(self, row: list[str]) -> bool:
        """
        Line starting with # are comments
        """
        return row[0][:1] == "#"

    def _is_row_valid(self, row: list[str]) -> bool:
        """
        If a line is strictly shorter than 3, it is not a valid entry
        """
        if len(row) >= 3:
            return True

        string_row: str = "".join(row)
        logger.warning(f"Skipping: incomplete entry for {string_row}")
        return False

    def _is_row_active(self, row: list[str]) -> bool:
        """
        A row is active if it is of length 3 or if the date of the row is not in the past.
        """
        if len(row) == 3:
            return True

        path = row[0]
        date = row[3]
        try:
            expire: datetime = datetime.fromisoformat(date).replace(tzinfo=UTC)

        except ValueError:
            logger.warning(f"Skipping: invalid date entry for {path}: {date}")
            return False

        if expire < self.today:
            logger.warning(f"Info: expired date entry for {date}")
            return False

        return True

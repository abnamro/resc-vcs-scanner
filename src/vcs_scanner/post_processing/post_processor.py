from argparse import Namespace

from resc_backend.resc_web_service.schema.finding import FindingBase

from vcs_scanner.helpers.providers.rule_tag import RuleTagProvider
from vcs_scanner.post_processing.processor_interface import PostProcessingStatus, Processor


class PostProcessor:
    def __init__(self, rule_tag_provider: RuleTagProvider):
        self.rule_tag_provider = rule_tag_provider

    def run(self, findings: list[FindingBase]) -> list[FindingBase]:
        processors: dict[str, Processor] = {
            # Processor classes go here that follow the Processor interface with the tag as key in the dictionary
        }

        output: list[FindingBase] = []
        rule_tags = self.rule_tag_provider.get_rule_tags()

        for finding in findings:
            tags = rule_tags.get(finding.rule_name, [])
            status = PostProcessingStatus.NOT_PROCESSED

            for tag in tags:
                processor = processors.get(tag, None)
                if processor is None:
                    # Tag has no processor, check next tag
                    continue

                status = processor.process_finding(finding)
                if status == PostProcessingStatus.TRUE_POSITIVE:
                    # add finding to output list and continue to next finding
                    output.append(finding)
                    break
                elif status == PostProcessingStatus.FALSE_POSITIVE:
                    # ignore this finding and continue to next finding
                    break

            if status == PostProcessingStatus.NOT_PROCESSED:
                # no processor is applicable, add finding to output
                output.append(finding)

        return output

    @staticmethod
    def make(args: Namespace) -> "PostProcessor":
        """
            Get the PostProcessor given the args provided.
        :param args:
            Namespace object containing the CLI arguments
        """
        rule_tag_provider = RuleTagProvider()
        rule_tag_provider.load(args.gitleaks_rules_path)

        return PostProcessor(rule_tag_provider)

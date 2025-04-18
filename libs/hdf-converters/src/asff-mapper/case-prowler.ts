import {encode} from 'html-entities';
import * as _ from 'lodash';

import {DEFAULT_UPDATE_REMEDIATION_NIST_TAGS} from '../utils/global';

const desc = () => ' ';

function subfindingsCodeDesc(finding: unknown) {
  return encode(_.get(finding, 'Description'));
}

function findingId(finding: unknown) {
  const generatorId = _.get(finding, 'GeneratorId') as unknown as string;
  const hyphenIndex = generatorId.indexOf('-');
  return encode(generatorId.slice(hyphenIndex + 1));
}

function productName(
  findings: Record<string, unknown> | Record<string, unknown>[]
) {
  const finding = Array.isArray(findings) ? findings[0] : findings;
  return encode(_.get(finding, 'ProductFields.ProviderName') as string);
}

function filename(
  findingInfo: [Record<string, unknown>, Record<string, unknown>[]]
) {
  return `${productName(findingInfo[1])}.json`;
}

function meta(): Record<string, string> {
  return {name: 'Prowler', title: 'Prowler Findings'};
}


function findingNistTag(finding: unknown): string[] {
  const relatedRequirements = _.get(finding, 'Resources[0].RelatedRequirements') as string[] | undefined;
  
  if (!relatedRequirements || !Array.isArray(relatedRequirements)) {
    return DEFAULT_UPDATE_REMEDIATION_NIST_TAGS;
  }
  
  const nistRelatedControls = relatedRequirements.find((x: string) => x.startsWith("NIST-800-53-Revision-5")) || null;
  
  if (typeof nistRelatedControls !== 'string') {
    return DEFAULT_UPDATE_REMEDIATION_NIST_TAGS;
  } else {
    return nistRelatedControls
      .replace(/NIST-800-53-Revision-5 /g, "")
      .replace(/_/g, "-")
      .toUpperCase()
      .split(" ");
  }
}

// eslint-disable-next-line @typescript-eslint/ban-types
export function getProwler(): Record<string, (...inputs: any) => any> {
  return {
    subfindingsCodeDesc,
    findingId,
    productName,
    desc,
    filename,
    meta,
    findingNistTag
  };
}

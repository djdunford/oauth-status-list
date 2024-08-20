import { DisclosureFrame } from '@sd-jwt/types';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { createSignerVerifier, digest, generateSalt } from "./utils";
import {StatusList} from "@sd-jwt/jwt-status-list";

const MAX_STATUS_LIST_SIZE = 10

export const runDemo = async () => {

  // initialise status list with 2-bits per status, values as follows:
  // 0 - ISSUED
  // 1 - SUSPENDED (temporarily)
  // 2 - REVOKED (permanently)
  // 3 - status slot UNUSED (i.e. not allocated)
  const statusList = new StatusList(Array.apply(null, Array(MAX_STATUS_LIST_SIZE)).map(() => 3), 2)

  const { signer, verifier } = await createSignerVerifier();

  // Create SDJwt instance for use
  const sdjwt = new SDJwtVcInstance({
    signer,
    verifier,
    signAlg: 'EdDSA',
    hasher: digest,
    hashAlg: 'SHA-256',
    saltGenerator: generateSalt,
  });

  // identifier of the issuer
  const iss = 'University';

  // issuance time
  const iat = new Date().getTime() / 1000;

  //unique identifier of the schema
  const vct = 'University-Degree';

  // Issuer defines the claims object with the user's information
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // set statusList for new VC as index 1 (i.e. second position in the array)
  statusList.setStatus(1, 0)

  // Issuer defines the disclosure frame to specify which claims can be disclosed/undisclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'lastname', 'ssn'],
  };

  // Issuer issues a signed JWT credential with the specified claims and disclosure frame
  // returns an encoded JWT
  const credential = await sdjwt.issue(
    {iss, iat, vct, ...claims},
    disclosureFrame,
  );

  // Holder may validate the credential from the issuer
  const valid = await sdjwt.validate(credential);

  // Holder defines the presentation frame to specify which claims should be presented
  // The list of presented claims must be a subset of the disclosed claims
  // const presentationFrame = ['firstname', 'ssn'];
  const presentationFrame = {
    firstname: true,
    ssn: true
  }

  // Holder creates a presentation using the issued credential and the presentation frame
  // returns an encoded SD JWT.
  const presentation = await sdjwt.present(credential, presentationFrame);

  // Verifier can verify the presentation using the Issuer's public key
  const verified = await sdjwt.verify(presentation);

  console.log("credential", credential)
  console.log("valid", valid)
  console.log("presentation", presentation)
  console.log("verified", verified)
  console.log("status list", statusList)
}

runDemo().then(() => {
  console.log("Demo complete")
}).catch((e) => {
  console.log("An error occurred", {e})
})

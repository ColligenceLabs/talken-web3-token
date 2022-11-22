import Base64 from 'base-64'
// import {
//   hashPersonalMessage,
//   toBuffer,
//   fromRpcSig,
//   ecrecover,
//   publicToAddress,
//   bufferToHex
// } from 'ethereumjs-util';
import * as EthUtil from 'ethereumjs-util';
import toHex from 'to-hex';
import { DecrypterResult } from '../interfaces';
import { parseBody } from './verify'

const getVersion = (body: string): number => {
  // @ts-ignore
  const [ str ] = body.match(/Web3[\s-]+Token[\s-]+Version: \d/);

  return Number(str.replace(' ', '').split(':')[1]);
}

export const decrypt = (token: string): DecrypterResult => {
  if(!token || !token.length) {
    throw new Error('Token required.')
  }

  const base64_decoded = Base64.decode(token);

  if(!base64_decoded || !base64_decoded.length) {
    throw new Error('Token malformed (must be base64 encoded)')
  }

  let body: string, signature: string;

  try {
    ({ body, signature } = JSON.parse(base64_decoded));
  } catch (error) {
    throw new Error('Token malformed (unparsable JSON)')
  }

  if(!body || !body.length) {
    throw new Error('Token malformed (empty message)')
  }

  if(!signature || !signature.length) {
    throw new Error('Token malformed (empty signature)')
  }

  const lines = body.split('\n');
  const parsed_body = parseBody(lines);
  const prefix = (parsed_body.wallet === 'kaikas') ? kaikasSignPrefix : signPrefix;

  const msgBuffer = EthUtil.toBuffer('0x' + toHex(body));
  // const msgHash = hashPersonalMessage(msgBuffer);
  const msgHash = hashPersonalMessagePrefix(msgBuffer, prefix);
  const signatureBuffer = EthUtil.toBuffer(signature);
  const signatureParams = EthUtil.fromRpcSig(signatureBuffer as any);

  const publicKey = EthUtil.ecrecover(
    msgHash,
    signatureParams.v,
    signatureParams.r,
    signatureParams.s
  );
  const addressBuffer = EthUtil.publicToAddress(publicKey);
  const address = EthUtil.bufferToHex(addressBuffer).toLowerCase();

  const version = getVersion(body);

  return {
    version,
    address,
    body,
    signature
  }
}

const kaikasSignPrefix = '\x19Klaytn Signed Message:\n'
const signPrefix = '\x19Ethereum Signed Message:\n'

export const assertIsBuffer = function (input: any) {
  if (!Buffer.isBuffer(input)) {
    const msg = `This method only supports Buffer but input was: ${input}`
    throw new Error(msg)
  }
}

export const hashPersonalMessagePrefix = function(message: any, signPrefix: any) {
  assertIsBuffer(message)
  const prefix = Buffer.from(
      `${signPrefix}${message.length.toString()}`,
      'utf-8'
  )
  return EthUtil.keccak(Buffer.concat([prefix, message]))
}

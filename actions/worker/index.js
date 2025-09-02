'use strict'

const { worker, SourceCorruptError } = require('@adobe/asset-compute-sdk')
const fs = require('fs').promises
const { createC2pa, ManifestBuilder, SigningAlgorithm } = require('c2pa-node')
const { readFile } = require('node:fs/promises');
const fse = require('fs-extra');
const FormData = require('form-data');
const fetch = require('@adobe/node-fetch-retry');
const util = require('util');
const exec = util.promisify(require('child_process').exec);
const { Core } = require('@adobe/aio-sdk');

const logger = Core.Logger('main', 'info');

// === C2PA manifest integration helpers (CLI-based) ===
const CLIENT_ID = "asset_compute_cai_integration";
const AUTH_GRANT_TYPE =  "authorization_code";
const AUTH_STAGE_ENDPOINT = "https://ims-na1-stg1.adobelogin.com";
const AUTH_PROD_ENDPOINT = "https://ims-na1.adobelogin.com";
const STAGE_TIER = "STAGE";
const PROD_TIER = "PROD";

function extractContentProvenanceActiveManifestContents(c2paMetadata) {
  if (!c2paMetadata) return null;
  // Best-effort extraction: return the active manifest content if present
  if (c2paMetadata.active_manifest) {
    return c2paMetadata.active_manifest;
  }
  return null;
}

async function executeJsonOutputCommand(command) {
  let result = null;
  try {
    const { stdout } = await exec(command);
    if (stdout) {
      const trimmed = stdout.trim();
      if (trimmed !== '') {
        result = JSON.parse(trimmed);
      }
    }
  } catch (_error) {
    // swallow errors; caller handles null result
  }
  return result;
}

async function exchangeServiceTokenForSignature(signParams) {
  if(!signParams || !signParams.clientSecret || !signParams.accessCode || !signParams.tier) {
    throw new Error('Incomplete C2PA signing information');
  }

  let adobeLoginHost = '';
  const tier = signParams.tier.toUpperCase();
  if(tier === PROD_TIER) {
    adobeLoginHost = AUTH_PROD_ENDPOINT;
  } else if(tier === STAGE_TIER) {
    adobeLoginHost = AUTH_STAGE_ENDPOINT;
  } else {
    throw Error(`Unable to exchange service token: ${signParams.tier} is not a valid tier (only stage or prod are supported)`);
  }

  const form = new FormData();
  form.append('grant_type', AUTH_GRANT_TYPE);
  form.append('client_id', CLIENT_ID);
  form.append('client_secret', signParams.clientSecret);
  form.append('code', signParams.accessCode);

  const res = await fetch(`${adobeLoginHost}/ims/token/v3`, {
    method: 'post',
    body: form
  });

  if(!res){
    throw Error('No response from token exchange service');
  }
  if (res.ok) {
    const json = await res.json();
    return json.access_token;
  } else {
    const json = await res.json();
    if (res.status === 400 && json && json.error === 'invalid_client' && json.error_description === 'invalid client_secret parameter') {
      throw Error('Unable to exchange service token, client_secret rejected');
    } else {
      throw Error(`Unable to exchange service token: ${res.status} ${res.statusText} ${JSON.stringify(json)}`);
    }
  }
}

function buildExtractionCommand(fileToProcess, jsonManifestPath, parentAsset=null, signParams = {}){
  let c2patoolCommand = '';
  if(parentAsset) {
    if(signParams.useInternalTooling){
      c2patoolCommand = `adobe_c2patool add-manifest --input "${fileToProcess}" --embed --config "${jsonManifestPath}" --force --output "${fileToProcess}" --parent "${parentAsset}"`;
    } else {
      c2patoolCommand = `c2patool "${fileToProcess}" --manifest "${jsonManifestPath}" -f -o "${fileToProcess}" -p "${parentAsset}"`;
    }
  } else {
    if(signParams.useInternalTooling){
      c2patoolCommand = `adobe_c2patool add-manifest --input "${fileToProcess}" --embed --config "${jsonManifestPath}" --force --output "${fileToProcess}"`;
    } else {
      c2patoolCommand = `c2patool "${fileToProcess}" --manifest "${jsonManifestPath}" -f -o "${fileToProcess}"`;
    }
  }
  return c2patoolCommand;
}

async function addAuthToCommand(inC2patoolCommand, signParams){
  let c2patoolCommand = inC2patoolCommand;
  if(signParams && signParams.useInternalTooling) {
    const nui_cai_auth_token = await exchangeServiceTokenForSignature(signParams);
    c2patoolCommand = `${inC2patoolCommand} --adobe-auth ${nui_cai_auth_token}`;
  }
  return c2patoolCommand;
}

async function addC2PAManifest(fileToProcess, jsonManifestPath, parentAsset=null, signParams={}) {
  let results = null;
  const c2patoolCommand = buildExtractionCommand(fileToProcess, jsonManifestPath, parentAsset, signParams);
  let finalC2patoolCommand = c2patoolCommand;
  try {
    finalC2patoolCommand = await addAuthToCommand(c2patoolCommand, signParams);
  } catch(_error) {
    throw new Error('Failed to add auth to C2PA command');
  }
  const jsonResult = await executeJsonOutputCommand(finalC2patoolCommand);
  if (jsonResult && Object.keys(jsonResult).length > 0) {
    results = jsonResult;
  }
  return results;
}

async function addAssetManifestToRendition(c2paMetadata, renditionPath, renditionName, tmpDir, signParams){
  if(!c2paMetadata) {
    return null;
  }

  let addedManifest = null;
  try {
    const assetActiveManifestContent = extractContentProvenanceActiveManifestContents(c2paMetadata);
    if(!assetActiveManifestContent){
      return null;
    }

    const assetActiveManifestPath = `${tmpDir}/${Date.now()}.${renditionName}.manifest.json`;
    await fse.writeJson(assetActiveManifestPath, assetActiveManifestContent);

    addedManifest = await addC2PAManifest(renditionPath, assetActiveManifestPath, null, signParams);

    if(signParams && signParams.cleanUpTmpFiles === true) {
      try {
        await fse.unlink(assetActiveManifestPath);
      } catch(err) {
        // ignore cleanup error
      }
    }
  } catch (_error) {
    // ignore errors, return null
  }

  return addedManifest;
}

function createRemoteSigner() {
  return {
    type: 'remote',
    async reserveSize() {
      const url = `https://my.signing.service/box-size`;
      const res = await fetch(url);
      const data = await res.json();
      return data.boxSize;
    },
    async sign({ reserveSize, toBeSigned }) {
      const url = `https://my.signing.service/sign?boxSize=${reserveSize}`;
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
        },
        body: toBeSigned,
      });
      return res.buffer();
    },
  };
}

// create a local signer
async function createLocalSigner() {
  // Using sample certificate files created for testing
  const [certificate, privateKey] = await Promise.all([
    readFile('./certs/certificate.pem'),
    readFile('./certs/private-key.pem'),
  ]);

  return {
    type: 'local',
    certificate,
    privateKey,
    algorithm: SigningAlgorithm.ES256,
    tsaUrl: 'http://timestamp.digicert.com',
  };
}

async function sign(asset, manifest, useLocalSigner = false) {
  const signer = useLocalSigner ? await createLocalSigner() : createRemoteSigner();
  const c2pa = createC2pa({
    signer,
  });

  const { signedAsset, signedManifest } = await c2pa.sign({
    asset,
    manifest,
  });
  
  return { signedAsset, signedManifest };
}

async function read(path, mimeType) {
  const c2pa = createC2pa();
  const buffer = await readFile(path);
  const result = await c2pa.read({ buffer, mimeType });
  return result || null;
}

exports.main = worker(async (source, rendition) => {
  // Example of how to throw a standard asset compute error
  // if e.g. the file is empty or broken.
  console.log('Starting worker');
  logger.info('Starting worker');

  const stats = await fs.stat(source.path)
  if (stats.size === 0) {
    throw new SourceCorruptError('source file is empty')
  }

  console.log('Processing file:', source.name);
  console.log('File size:', stats.size);
  console.log('MIME type:', source.mimeType);

  // Read C2PA data from the source file
  try {
    // capture source metadata for later use
    var sourceC2paMetadata = await read(source.path, source.mimeType || 'image/jpeg');
  } catch (error) {
    console.error('Error reading C2PA data:', error);
  }

  // Sign the asset with C2PA manifest
  try {
    const buffer = await readFile(source.path);
    const asset = { buffer, mimeType: source.mimeType || 'image/jpeg' };

    const manifest = new ManifestBuilder(
      {
        claim_generator: 'htx-cai-asset-compute/1.0.0',
        format: source.mimeType || 'image/jpeg',
        title: source.name || 'signed-asset',
        assertions: [
          {
            label: 'c2pa.actions',
            data: {
              actions: [
                {
                  action: 'c2pa.created',
                },
              ],
            },
          },
          {
            label: 'com.custom.my-assertion',
            data: {
              description: 'My custom test assertion',
              version: '1.0.0',
            },
          },
        ],
      },
      { vendor: 'cai' },
    );

    // Use local signer by default, can be configured via rendition.instructions
    const useLocalSigner = rendition.instructions?.useLocalSigner ?? true;
    const { signedAsset } = await sign(asset, manifest, useLocalSigner);
    
    // Write the signed asset to the rendition
    await fs.writeFile(rendition.path, signedAsset.buffer);
    
    console.log('Asset signed successfully with C2PA manifest');
  } catch (error) {
    console.error('Error signing asset:', error);
    // Fallback to copying the original file if signing fails
    await fs.copyFile(source.path, rendition.path);
  }

  // Optionally copy the source asset's active manifest onto the rendition via c2patool
  try {
    const shouldAddSourceManifest = rendition.instructions?.addSourceManifest === true;
    if (shouldAddSourceManifest && sourceC2paMetadata) {
      const tmpDir = '/tmp';
      const signParams = rendition.instructions?.c2paSignParams || {};
      await addAssetManifestToRendition(sourceC2paMetadata, rendition.path, rendition.name || 'rendition', tmpDir, signParams);
    }
  } catch (err) {
    console.error('Failed to add source C2PA manifest to rendition:', err);
  }

  console.log('File processed successfully');

  // Tip: custom worker parameters are available in rendition.instructions
})

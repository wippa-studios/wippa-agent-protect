import type { RegistryCatalog, RegistryEntry } from './types';
import { authHeaders } from './auth';

export interface RegistryConfig {
  registryUrl: string;
  enterpriseApiKey?: string;
  org?: string;
}

export async function fetchCatalog(config: RegistryConfig): Promise<RegistryCatalog> {
  const url = `${config.registryUrl}/api/v1/registry/catalog`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...authHeaders({ enterpriseApiKey: config.enterpriseApiKey, org: config.org }),
  };

  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      throw new Error(`Registry catalog fetch failed: ${res.status} ${res.statusText}`);
    }
      return await res.json() as RegistryCatalog;
  } catch (err: any) {
    throw new Error(`Registry error: ${err?.message || 'Unknown'}`);
  }
}

export async function lookupImage(
  imageName: string,
  imageSha256: string,
  config: RegistryConfig
): Promise<RegistryEntry | null> {
  const catalog = await fetchCatalog(config);
  return catalog.entries.find(
    e => e.name === imageName && e.imageSha256 === imageSha256 && e.approved
  ) || null;
}

export async function verifyImage(
  imageName: string,
  imageSha256: string,
  config: RegistryConfig
): Promise<{ approved: boolean; entry?: RegistryEntry; error?: string }> {
  try {
    const entry = await lookupImage(imageName, imageSha256, config);
    if (!entry) {
      return { approved: false, error: `Image ${imageName} not found in approved registry` };
    }
    return { approved: true, entry };
  } catch (err: any) {
    return { approved: false, error: err?.message || 'Registry verification failed' };
  }
}

export async function fetchApprovedImages(config: RegistryConfig): Promise<RegistryEntry[]> {
  const catalog = await fetchCatalog(config);
  return catalog.entries.filter(e => e.approved);
}

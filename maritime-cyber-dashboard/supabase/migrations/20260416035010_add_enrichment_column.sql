-- Add enrichment JSONB column to store threat intelligence results from VirusTotal / Shodan / AbuseIPDB
alter table public.incidents
  add column if not exists enrichment jsonb default null;

-- incidents
create table if not exists public.incidents (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  threat_group text,
  severity text not null check (severity in ('Critical', 'High', 'Medium', 'Low')),
  sector text not null check (sector in ('Maritime', 'Energy', 'Transportation', 'Water', 'Healthcare', 'Financial', 'Telecom', 'Government', 'Manufacturing')),
  attack_vector text not null check (attack_vector in ('Ransomware', 'Phishing', 'Supply Chain', 'Vulnerability Exploitation', 'DDoS', 'Insider Threat', 'Malware', 'Network Intrusion', 'IoT/OT Compromise')),
  target_organization text,
  target_country text,
  iocs jsonb,
  source_url text,
  created_at timestamptz not null default now()
);

-- maritime_assets
create table if not exists public.maritime_assets (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  asset_type text not null check (asset_type in ('Port', 'Vessel', 'Terminal', 'Offshore Platform', 'Shipping Company')),
  country text,
  exposure_score integer not null default 0 check (exposure_score >= 0 and exposure_score <= 100),
  vulnerabilities jsonb,
  created_at timestamptz not null default now()
);

-- threat_groups
create table if not exists public.threat_groups (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  ttps jsonb,
  victim_count integer not null default 0,
  last_activity timestamptz not null default now(),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- enable row level security
alter table public.incidents enable row level security;
alter table public.maritime_assets enable row level security;
alter table public.threat_groups enable row level security;

-- service role bypass (used by the ingest API)
create policy "service role full access" on public.incidents for all using (true);
create policy "service role full access" on public.maritime_assets for all using (true);
create policy "service role full access" on public.threat_groups for all using (true);

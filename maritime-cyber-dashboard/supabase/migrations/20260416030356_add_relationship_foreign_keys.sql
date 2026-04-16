-- Add foreign key columns to incidents
alter table public.incidents
  add column if not exists threat_group_id uuid references public.threat_groups(id) on delete set null,
  add column if not exists maritime_asset_id uuid references public.maritime_assets(id) on delete set null;

-- Indexes for join performance
create index if not exists incidents_threat_group_id_idx on public.incidents(threat_group_id);
create index if not exists incidents_maritime_asset_id_idx on public.incidents(maritime_asset_id);
-- Enable Supabase Realtime on all three dashboard tables
alter publication supabase_realtime add table public.incidents;
alter publication supabase_realtime add table public.maritime_assets;
alter publication supabase_realtime add table public.threat_groups;
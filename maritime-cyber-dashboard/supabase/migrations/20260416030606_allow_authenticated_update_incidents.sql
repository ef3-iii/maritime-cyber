-- Allow authenticated users to update relationship fields on incidents
create policy "authenticated users can update incidents"
  on public.incidents
  for update
  to authenticated
  using (true)
  with check (true);

-- Allow authenticated users to read all three tables via browser client
create policy "authenticated users can read incidents"
  on public.incidents for select to authenticated using (true);

create policy "authenticated users can read threat_groups"
  on public.threat_groups for select to authenticated using (true);

create policy "authenticated users can read maritime_assets"
  on public.maritime_assets for select to authenticated using (true);
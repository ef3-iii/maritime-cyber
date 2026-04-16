-- Partial unique index on source_url so N8N re-runs don't duplicate incidents.
-- NULL source_url rows are excluded (multiple manual incidents with no URL are fine).
create unique index if not exists incidents_source_url_unique
  on public.incidents (source_url)
  where source_url is not null;

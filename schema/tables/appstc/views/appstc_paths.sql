-- Simplified version
with recursive tree as (
  select
    appstc_id as id,
    array[appstc_id] as id_path,
    1 as depth
  from appstc
  where appstc_parent_appstc_id is null
  union all
  select
    appstc_id,
    id_path || array[appstc_id],
    depth + 1
  from appstc
  join tree
    on id = appstc_parent_appstc_id
)
select * from tree

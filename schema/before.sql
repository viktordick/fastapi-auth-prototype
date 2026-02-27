create or replace function public.db_username()
returns text
language plpgsql
strict
as $function$
begin
  return current_setting('dbutils.username', true);
end;
$function$;

create or replace function public.db_username(name text)
returns void
language plpgsql
as $function$
begin
  perform set_config('dbutils.username', name, false);
end;
$function$;

create or replace function db_create_fk_constraint(
  sourcetable text,
  targettable text,
  prefix text default null::text,
  mode char default 'c'
)
returns void
language plpgsql
as $function$
declare
  constraint_exist boolean;
  colname text;
  rule text;
begin
  sourcetable = quote_ident(sourcetable);
  targettable = quote_ident(targettable);
  colname = quote_ident(coalesce(prefix || '_', '') || targettable || '_id');
  mode := coalesce(mode, 'c');
  if mode not in ('r', 'c', 'n', 'a', '') then
    raise exception 'Invalid mode';
  end if;
  
  case mode
    when 'r' then rule = 'restrict';
    when 'n' then rule = 'set null';
    else rule = 'cascade';
  end case;

  -- Check if fk constraint already exists
  select
    exists(
      select
        pg_constraint.oid is not null
      from
        pg_constraint
      join pg_class
        on pg_class.oid = pg_constraint.conrelid
      where
        pg_constraint.contype = 'f'
      and
        pg_class.relname = sourcetable
      and
        pg_constraint.conname = colname
      and
        pg_constraint.confdeltype = mode
    )
  into
    constraint_exist;

  if not constraint_exist then
    -- Delete constraint
    execute
      'alter table ' || sourcetable ||
      ' drop constraint if exists ' || colname;

    -- Create new constraint
    execute
      'alter table ' || sourcetable ||
      ' add constraint ' || colname ||
      ' foreign key (' || sourcetable || '_' || colname || ')' ||
      ' references ' || targettable ||
      ' on update cascade' ||
      ' on delete ' || rule;
  end if;

end;
$function$;


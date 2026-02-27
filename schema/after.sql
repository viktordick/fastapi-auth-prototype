-- Stuff to do after perfact-dbschema patch

alter table appuser alter column appuser_name set not null;
alter table appgroup alter column appgroup_zoperole set not null;
alter table appperm alter column appperm_name set not null;

alter table appuserxperm alter column appuserxperm_appuser_id set not null;
alter table appuserxperm alter column appuserxperm_appperm_id set not null;
select db_create_fk_constraint('appuserxperm', 'appuser');
select db_create_fk_constraint('appuserxperm', 'appperm');
create index if not exists appuserxperm_appuser_id on appuserxperm (appuserxperm_appuser_id);
create index if not exists appuserxperm_appperm_id on appuserxperm (appuserxperm_appperm_id);
create unique index if not exists appuserxperm_appuser_id_appperm_id on appuserxperm (appuserxperm_appuser_id, appuserxperm_appperm_id);

alter table apppermxgroup alter column apppermxgroup_appgroup_id set not null;
alter table apppermxgroup alter column apppermxgroup_appperm_id set not null;
select db_create_fk_constraint('apppermxgroup', 'appperm');
select db_create_fk_constraint('apppermxgroup', 'appgroup');
create index if not exists apppermxgroup_appgroup_id on apppermxgroup (apppermxgroup_appgroup_id);
create index if not exists apppermxgroup_appperm_id on apppermxgroup (apppermxgroup_appperm_id);
create unique index if not exists apppermxgroup_appgroup_id_appperm_id on apppermxgroup (apppermxgroup_appgroup_id, apppermxgroup_appperm_id);

alter table appuserlogin alter column appuserlogin_appuser_id set not null;
select db_create_fk_constraint('appuserlogin', 'appuser');
create index if not exists appuserlogin_appuser_id on appuserlogin (appuserlogin_appuser_id);
create index if not exists appuserlogin_cookie on appuserlogin (appuserlogin_cookie);
create index if not exists appuserlogin_nextcookie on appuserlogin (appuserlogin_nextcookie);

alter table appuserkey alter column appuserkey_appuser_id set not null;
select db_create_fk_constraint('appuserkey', 'appuser');
create index if not exists appuserkey_appuser_id on appuserkey (appuserkey_appuser_id);
create index if not exists appuserkey_key on appuserkey (appuserkey_key);

alter table appstc alter column appstc_name set not null;
select db_create_fk_constraint('appstc', 'appstc', 'parent');
create index if not exists appstc_parent_appstc_id on appstc (appstc_parent_appstc_id);
create unique index appstc_name_root on appstc (appstc_name) where appstc_parent_appstc_id is null;
create unique index appstc_parent_appstc_id_name on appstc (appstc_parent_appstc_id, appstc_name);

alter table appuserxstc alter column appuserxstc_appuser_id set not null;
alter table appuserxstc alter column appuserxstc_appstc_id set not null;
select db_create_fk_constraint('appuserxstc', 'appuser');
select db_create_fk_constraint('appuserxstc', 'appstc');
create index if not exists appuserxstc_appuser_id on appuserxstc (appuserxstc_appuser_id);
create index if not exists appuserxstc_appstc_id on appuserxstc (appuserxstc_appstc_id);
create unique index if not exists appuserxstc_appuser_id_appstc_id on appuserxstc (appuserxstc_appuser_id, appuserxstc_appstc_id);

alter table apppermxstc alter column apppermxstc_appperm_id set not null;
alter table apppermxstc alter column apppermxstc_appstc_id set not null;
select db_create_fk_constraint('apppermxstc', 'appperm');
select db_create_fk_constraint('apppermxstc', 'appstc');
create index if not exists apppermxstc_appperm_id on apppermxstc (apppermxstc_appperm_id);
create index if not exists apppermxstc_appstc_id on apppermxstc (apppermxstc_appstc_id);
create unique index if not exists apppermxstc_appperm_id_appstc_id on apppermxstc (apppermxstc_appperm_id, apppermxstc_appstc_id);

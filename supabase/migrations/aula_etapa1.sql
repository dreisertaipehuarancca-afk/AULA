-- AULA · Etapa 1: cuentas por rol, cursos, materiales, tareas, entregas y notas
-- Tablas con prefijo aula_ (no tocan turnos/reservas/espera)

create table public.aula_perfiles (
  id uuid primary key references auth.users(id) on delete cascade,
  rol text not null check (rol in ('director','profesor','alumno')),
  nombre text not null check (length(nombre) between 2 and 80),
  usuario text not null unique check (usuario ~ '^[a-z0-9._]{3,30}$'),
  grado smallint check (grado between 1 and 5),
  seccion text check (seccion ~ '^[A-Z]$'),
  puntos int not null default 0,
  creado timestamptz not null default now(),
  check (rol <> 'alumno' or (grado is not null and seccion is not null))
);

create table public.aula_cursos (
  id bigint generated always as identity primary key,
  nombre text not null check (length(nombre) between 2 and 60),
  grado smallint not null check (grado between 1 and 5),
  seccion text not null check (seccion ~ '^[A-Z]$'),
  profesor_id uuid references public.aula_perfiles(id) on delete set null,
  color text not null default '#5b5bd6' check (color ~ '^#[0-9a-fA-F]{6}$'),
  icono text not null default '📘' check (length(icono) <= 8),
  creado timestamptz not null default now()
);

create table public.aula_materiales (
  id bigint generated always as identity primary key,
  curso_id bigint not null references public.aula_cursos(id) on delete cascade,
  titulo text not null check (length(titulo) between 2 and 120),
  tipo text not null check (tipo in ('texto','link','video','archivo')),
  contenido text check (length(contenido) <= 8000),
  url text check (url is null or url ~ '^https://'),
  archivo text,
  autor uuid default auth.uid() references public.aula_perfiles(id) on delete set null,
  creado timestamptz not null default now()
);

create table public.aula_tareas (
  id bigint generated always as identity primary key,
  curso_id bigint not null references public.aula_cursos(id) on delete cascade,
  titulo text not null check (length(titulo) between 2 and 120),
  descripcion text check (length(descripcion) <= 4000),
  vence timestamptz not null,
  puntos smallint not null default 10 check (puntos between 0 and 100),
  autor uuid default auth.uid() references public.aula_perfiles(id) on delete set null,
  creado timestamptz not null default now()
);

create table public.aula_entregas (
  id bigint generated always as identity primary key,
  tarea_id bigint not null references public.aula_tareas(id) on delete cascade,
  alumno_id uuid not null references public.aula_perfiles(id) on delete cascade,
  texto text check (length(texto) <= 8000),
  archivo text,
  entregado timestamptz not null default now(),
  nota numeric(4,1) check (nota between 0 and 20),
  comentario text check (length(comentario) <= 1000),
  calificado timestamptz,
  unique (tarea_id, alumno_id)
);

create index on public.aula_cursos (grado, seccion);
create index on public.aula_cursos (profesor_id);
create index on public.aula_materiales (curso_id);
create index on public.aula_tareas (curso_id, vence);
create index on public.aula_entregas (alumno_id);

-- Ayudantes de permisos
create or replace function public.aula_mi_rol() returns text
language sql stable security definer set search_path = public as $$
  select rol from aula_perfiles where id = auth.uid()
$$;

create or replace function public.aula_ve_curso(c bigint) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from aula_cursos k join aula_perfiles p on p.id = auth.uid()
    where k.id = c and (p.rol = 'director' or k.profesor_id = p.id
      or (p.rol = 'alumno' and p.grado = k.grado and p.seccion = k.seccion)))
$$;

create or replace function public.aula_dicta(c bigint) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from aula_cursos k join aula_perfiles p on p.id = auth.uid()
    where k.id = c and (p.rol = 'director' or (p.rol = 'profesor' and k.profesor_id = p.id)))
$$;

create or replace function public.aula_cid(n text) returns bigint
language sql immutable set search_path = public as $$
  select case when split_part(n, '/', 1) ~ '^c[0-9]{1,12}$' then substr(split_part(n, '/', 1), 2)::bigint end
$$;

-- RLS
alter table public.aula_perfiles enable row level security;
alter table public.aula_cursos enable row level security;
alter table public.aula_materiales enable row level security;
alter table public.aula_tareas enable row level security;
alter table public.aula_entregas enable row level security;

revoke all on public.aula_perfiles, public.aula_cursos, public.aula_materiales, public.aula_tareas, public.aula_entregas from anon, authenticated;
grant select on public.aula_perfiles, public.aula_entregas to authenticated;
grant select, insert, update, delete on public.aula_cursos, public.aula_materiales, public.aula_tareas to authenticated;

create policy perf_ver on public.aula_perfiles for select to authenticated using (
  id = auth.uid() or aula_mi_rol() = 'director'
  or (aula_mi_rol() = 'profesor' and exists (select 1 from aula_cursos k
       where k.profesor_id = auth.uid() and k.grado = aula_perfiles.grado and k.seccion = aula_perfiles.seccion))
  or (rol = 'profesor' and exists (select 1 from aula_cursos k where k.profesor_id = aula_perfiles.id and aula_ve_curso(k.id))));

create policy cur_ver on public.aula_cursos for select to authenticated using (aula_ve_curso(id));
create policy cur_dir on public.aula_cursos for all to authenticated using (aula_mi_rol() = 'director') with check (aula_mi_rol() = 'director');

create policy mat_ver on public.aula_materiales for select to authenticated using (aula_ve_curso(curso_id));
create policy mat_ins on public.aula_materiales for insert to authenticated with check (aula_dicta(curso_id));
create policy mat_upd on public.aula_materiales for update to authenticated using (aula_dicta(curso_id)) with check (aula_dicta(curso_id));
create policy mat_del on public.aula_materiales for delete to authenticated using (aula_dicta(curso_id));

create policy tar_ver on public.aula_tareas for select to authenticated using (aula_ve_curso(curso_id));
create policy tar_ins on public.aula_tareas for insert to authenticated with check (aula_dicta(curso_id));
create policy tar_upd on public.aula_tareas for update to authenticated using (aula_dicta(curso_id)) with check (aula_dicta(curso_id));
create policy tar_del on public.aula_tareas for delete to authenticated using (aula_dicta(curso_id));

create policy ent_ver on public.aula_entregas for select to authenticated using (
  alumno_id = auth.uid() or exists (select 1 from aula_tareas t where t.id = tarea_id and aula_dicta(t.curso_id)));

-- Entregar tarea (alumno)
create or replace function public.aula_entregar(p_tarea bigint, p_texto text, p_archivo text default null)
returns text language plpgsql security definer set search_path = public as $$
declare c bigint; e aula_entregas;
begin
  if aula_mi_rol() is distinct from 'alumno' then return 'no_alumno'; end if;
  select curso_id into c from aula_tareas where id = p_tarea;
  if c is null or not aula_ve_curso(c) then return 'no_curso'; end if;
  if coalesce(length(trim(p_texto)), 0) = 0 and p_archivo is null then return 'vacio'; end if;
  if p_archivo is not null and (aula_cid(p_archivo) is distinct from c or split_part(p_archivo, '/', 2) <> 'e'
     or split_part(p_archivo, '/', 3) <> auth.uid()::text) then return 'archivo_malo'; end if;
  select * into e from aula_entregas where tarea_id = p_tarea and alumno_id = auth.uid();
  if e.nota is not null then return 'ya_calificada'; end if;
  insert into aula_entregas (tarea_id, alumno_id, texto, archivo)
  values (p_tarea, auth.uid(), left(p_texto, 8000), p_archivo)
  on conflict (tarea_id, alumno_id) do update set texto = excluded.texto, archivo = coalesce(excluded.archivo, aula_entregas.archivo), entregado = now();
  return 'ok';
end $$;

-- Calificar (profesor del curso o director)
create or replace function public.aula_calificar(p_entrega bigint, p_nota numeric, p_comentario text default null)
returns text language plpgsql security definer set search_path = public as $$
declare c bigint;
begin
  select t.curso_id into c from aula_entregas e join aula_tareas t on t.id = e.tarea_id where e.id = p_entrega;
  if c is null or not aula_dicta(c) then return 'no_permiso'; end if;
  if p_nota is null or p_nota < 0 or p_nota > 20 then return 'nota_mala'; end if;
  update aula_entregas set nota = round(p_nota, 1), comentario = left(p_comentario, 1000), calificado = now() where id = p_entrega;
  return 'ok';
end $$;

revoke all on function public.aula_entregar(bigint, text, text), public.aula_calificar(bigint, numeric, text) from public, anon;
grant execute on function public.aula_entregar(bigint, text, text), public.aula_calificar(bigint, numeric, text) to authenticated;
revoke all on function public.aula_mi_rol(), public.aula_ve_curso(bigint), public.aula_dicta(bigint) from public, anon;
grant execute on function public.aula_mi_rol(), public.aula_ve_curso(bigint), public.aula_dicta(bigint) to authenticated;

-- Archivos privados (materiales y entregas)
insert into storage.buckets (id, name, public, file_size_limit)
values ('aula', 'aula', false, 20971520) on conflict (id) do nothing;

create policy aula_leer on storage.objects for select to authenticated using (
  bucket_id = 'aula' and aula_cid(name) is not null and (
    (split_part(name, '/', 2) = 'm' and aula_ve_curso(aula_cid(name)))
    or (split_part(name, '/', 2) = 'e' and (split_part(name, '/', 3) = auth.uid()::text or aula_dicta(aula_cid(name))))));
create policy aula_subir on storage.objects for insert to authenticated with check (
  bucket_id = 'aula' and aula_cid(name) is not null and (
    (split_part(name, '/', 2) = 'm' and aula_dicta(aula_cid(name)))
    or (split_part(name, '/', 2) = 'e' and split_part(name, '/', 3) = auth.uid()::text
        and aula_mi_rol() = 'alumno' and aula_ve_curso(aula_cid(name)))));
create policy aula_borrar on storage.objects for delete to authenticated using (
  bucket_id = 'aula' and owner_id = auth.uid()::text);

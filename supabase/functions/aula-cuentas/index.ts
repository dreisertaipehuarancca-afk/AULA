// AULA · Cuentas: el director crea profesores y alumnos (usuario + contraseña, sin correo)
import { createClient } from 'npm:@supabase/supabase-js@2';

const URL_ = Deno.env.get('SUPABASE_URL')!;
const KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const DOM = '@aula.invalid';
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const out = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, 'Content-Type': 'application/json' } });

const ROLES = ['profesor', 'alumno'];
const okUser = (u: string) => /^[a-z0-9._]{3,30}$/.test(u);
const okPass = (p: string) => typeof p === 'string' && p.length >= 6 && p.length <= 72;
const clean = (s: unknown, n: number) => String(s ?? '').replace(/\s+/g, ' ').trim().slice(0, n);

function slug(nombre: string) {
  const p = nombre.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z ]/g, '').split(' ').filter(Boolean);
  return ((p[0] || 'alumno') + (p[1] ? '.' + p[1] : '')).slice(0, 24);
}
function clave() {
  const a = 'abcdefghjkmnpqrstuvwxyz', d = '23456789';
  const r = crypto.getRandomValues(new Uint8Array(7));
  let s = '';
  for (let i = 0; i < 4; i++) s += a[r[i] % a.length];
  for (let i = 4; i < 7; i++) s += d[r[i] % d.length];
  return s;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return out({ ok: true });
  if (req.method !== 'POST') return out({ error: 'metodo' }, 405);
  const db = createClient(URL_, KEY, { auth: { persistSession: false, autoRefreshToken: false } });
  let d: any; try { d = await req.json(); } catch { return out({ error: 'json' }, 400); }

  async function crear(rol: string, nombre: string, usuario: string, pass: string, grado?: number, seccion?: string) {
    if (!['director', ...ROLES].includes(rol)) return 'rol';
    nombre = clean(nombre, 80); usuario = clean(usuario, 30).toLowerCase();
    if (nombre.length < 2) return 'nombre';
    if (!okUser(usuario)) return 'usuario';
    if (!okPass(pass)) return 'clave';
    if (rol === 'alumno' && (!(grado! >= 1 && grado! <= 5) || !/^[A-Z]$/.test(seccion || ''))) return 'grado';
    const { data: ya } = await db.from('aula_perfiles').select('id').eq('usuario', usuario).maybeSingle();
    if (ya) return 'usuario_existe';
    const { data, error } = await db.auth.admin.createUser({ email: usuario + DOM, password: pass, email_confirm: true, user_metadata: { nombre } });
    if (error || !data.user) return 'auth:' + (error?.message || '?');
    const { error: e2 } = await db.from('aula_perfiles').insert({
      id: data.user.id, rol, nombre, usuario,
      grado: rol === 'alumno' ? grado : null, seccion: rol === 'alumno' ? seccion : null,
    });
    if (e2) { await db.auth.admin.deleteUser(data.user.id); return 'perfil:' + e2.message; }
    return 'ok';
  }

  // Primer ingreso: solo si todavía no existe ningún director
  if (d.accion === 'inicial') {
    const { count } = await db.from('aula_perfiles').select('id', { count: 'exact', head: true }).eq('rol', 'director');
    if ((count ?? 0) > 0) return out({ error: 'ya_hay_director' }, 403);
    return out({ r: await crear('director', d.nombre, d.usuario, d.clave) });
  }
  if (d.accion === 'hay_director') {
    const { count } = await db.from('aula_perfiles').select('id', { count: 'exact', head: true }).eq('rol', 'director');
    return out({ r: (count ?? 0) > 0 });
  }

  // El resto: solo el director
  const jwt = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const { data: u } = await db.auth.getUser(jwt);
  if (!u?.user) return out({ error: 'sesion' }, 401);
  const { data: yo } = await db.from('aula_perfiles').select('rol').eq('id', u.user.id).maybeSingle();
  if (yo?.rol !== 'director') return out({ error: 'no_director' }, 403);

  if (d.accion === 'crear') {
    if (!ROLES.includes(d.rol)) return out({ r: 'rol' });
    return out({ r: await crear(d.rol, d.nombre, d.usuario, d.clave, Number(d.grado), d.seccion) });
  }

  if (d.accion === 'lote') {
    // Lista de alumnos de un salón: genera usuario y contraseña para cada uno
    const nombres: string[] = (Array.isArray(d.nombres) ? d.nombres : []).map((n: unknown) => clean(n, 80)).filter((n: string) => n.length >= 2).slice(0, 60);
    const grado = Number(d.grado), seccion = String(d.seccion || '');
    if (!nombres.length) return out({ r: 'vacio' });
    const res: any[] = [];
    for (const n of nombres) {
      let base = slug(n), us = base, i = 1, r = '';
      for (; i < 50; i++) {
        const pass = clave();
        r = await crear('alumno', n, us, pass, grado, seccion);
        if (r === 'ok') { res.push({ nombre: n, usuario: us, clave: pass }); break; }
        if (r !== 'usuario_existe') { res.push({ nombre: n, error: r }); break; }
        us = (base.slice(0, 22) + (i + 1));
      }
    }
    return out({ r: 'ok', cuentas: res });
  }

  if (d.accion === 'clave') {
    const pass = okPass(d.clave) ? d.clave : clave();
    const { data: p } = await db.from('aula_perfiles').select('id,rol').eq('id', d.id).maybeSingle();
    if (!p || p.rol === 'director') return out({ r: 'no' });
    const { error } = await db.auth.admin.updateUserById(p.id, { password: pass });
    return out(error ? { r: 'error' } : { r: 'ok', clave: pass });
  }

  if (d.accion === 'borrar') {
    const { data: p } = await db.from('aula_perfiles').select('id,rol').eq('id', d.id).maybeSingle();
    if (!p || p.rol === 'director') return out({ r: 'no' });
    const { error } = await db.auth.admin.deleteUser(p.id);
    return out({ r: error ? 'error' : 'ok' });
  }

  return out({ error: 'accion' }, 400);
});

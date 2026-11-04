-- Corrects 20261104_patient_read_booked_slot.sql.
-- appointments.patient_id is patients.id (NOT the auth user id); the login id
-- lives in patients.user_id. Match through that link.
-- Apply in the Supabase SQL editor (or `supabase db push`).

create or replace function public.patient_owns_slot(p_slot_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.appointments a
    join public.patients p on p.id = a.patient_id
    where a.time_slot_id = p_slot_id
      and p.user_id = auth.uid()
  );
$$;

revoke all on function public.patient_owns_slot(uuid) from public, anon;
grant execute on function public.patient_owns_slot(uuid) to authenticated;

-- The policy from 20261104 already calls this function; recreate it to be safe.
drop policy if exists "patients read slot of own appointment" on public.time_slots;
create policy "patients read slot of own appointment"
  on public.time_slots
  for select
  to authenticated
  using (public.patient_owns_slot(id));

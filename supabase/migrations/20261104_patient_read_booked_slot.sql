-- Let a patient read the time slot attached to their own appointment.
--
-- Booking marks the slot is_available = false. If the existing time_slots
-- SELECT policy only exposes available slots, the appointment's joined slot
-- comes back null and the detail screen falls back to "Date TBC / Time TBC".
-- Apply in the Supabase SQL editor (or `supabase db push`).

-- SECURITY DEFINER avoids RLS recursion between appointments and time_slots.
create or replace function public.patient_owns_slot(p_slot_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.appointments a
    where a.time_slot_id = p_slot_id
      and a.patient_id = auth.uid()
  );
$$;

revoke all on function public.patient_owns_slot(uuid) from public, anon;
grant execute on function public.patient_owns_slot(uuid) to authenticated;

drop policy if exists "patients read slot of own appointment" on public.time_slots;
create policy "patients read slot of own appointment"
  on public.time_slots
  for select
  to authenticated
  using (public.patient_owns_slot(id));

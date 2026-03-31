// -----------------------------------------------------------------------
// app/page.tsx — Root page (the "/" route)
//
// This page has one job: send the user to /login immediately.
// Next.js's redirect() runs on the server before anything is shown,
// so the user never actually sees this page — they land straight on /login.
// -----------------------------------------------------------------------

import { redirect } from 'next/navigation'

export default function Home() {
  redirect('/login')
}

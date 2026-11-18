"use client";

import { Suspense } from "react";
import MissionControl from "@/components/MissionControl";

// The run-detail route: /runs?id={run_id}. MissionControl reads the id from
// the URL and drives everything itself; the Suspense boundary is required for
// the static export (useSearchParams in a prerendered client page).
export default function RunsPage() {
  return (
    <Suspense fallback={null}>
      <MissionControl />
    </Suspense>
  );
}

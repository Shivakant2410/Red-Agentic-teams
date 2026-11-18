import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MissionPanel } from "./MissionPanel";
import type { Finding, MissionDetail } from "@/lib/types";

/** Phase 8: mission-specific fields render HONESTLY — unavailable data shows
 *  unavailable states; confirmed findings are verifier-authority only. */
function mission(partial: Partial<MissionDetail>): MissionDetail {
  return {
    mission_id: "M-1", run_id: "M-1", run_ids: ["M-1"],
    engagement: "Lab", objective: "obj", status: "running",
    tasks: [], recent_events: [], ...partial,
  };
}

const finding = (id: string, confidence?: string): Finding =>
  ({ id, title: `F-${id}`, severity: "high", ...(confidence ? { confidence } : {}) });

describe("MissionPanel", () => {
  it("splits confirmed findings from not-yet-confirmed ones (verifier authority)", () => {
    render(<MissionPanel
      mission={mission({})}
      missionErr={null}
      findings={[
        finding("1", "confirmed"),
        finding("2", "confirmed"),
        finding("3", "pending_verification"),
        finding("4", "tentative"),
        finding("5", "falsified"),
        finding("6"),
      ]}
    />);
    expect(screen.getByText("confirmed 2")).toBeInTheDocument();
    expect(screen.getByText("awaiting verifier 1")).toBeInTheDocument();
    expect(screen.getByText(/in pipeline/i)).toBeInTheDocument();
  });

  it("shows the current task with specialist and attempt count", () => {
    render(<MissionPanel
      mission={mission({ tasks: [
        { id: "T-1", technique: "sqli", target: "/orders", status: "succeeded" },
        { id: "T-2", technique: "idor", target: "/invoices/1", status: "running",
          specialist: "exploit", attempts: 2 },
      ] })}
      missionErr={null}
      findings={[]}
    />);
    expect(screen.getByText("idor")).toBeInTheDocument();
    expect(screen.getByText("/invoices/1")).toBeInTheDocument();
    expect(screen.getByText(/exploit · attempt 2/i)).toBeInTheDocument();
    expect(screen.getByText("succeeded 1")).toBeInTheDocument();
    expect(screen.getByText("running 1")).toBeInTheDocument();
  });

  it("renders honest unavailable states when the mission record is absent", () => {
    render(<MissionPanel mission={null} missionErr="HTTP 404" findings={[]} />);
    expect(screen.getByText(/unavailable \(mission record not written yet\)/i)).toBeInTheDocument();
    expect(screen.getByText(/no task snapshot available yet/i)).toBeInTheDocument();
    expect(screen.getByText(/— not exposed by the api/i)).toBeInTheDocument();  // budget honesty
    expect(screen.getByText(/mission record unavailable/i)).toBeInTheDocument();
    expect(screen.getByText(/mission\.json is written by the driver/i)).toBeInTheDocument();
  });

  it("shows stop reason and journal tail for replanning visibility", () => {
    render(<MissionPanel
      mission={mission({
        halt_reason: "unresolved_verification",
        recent_events: [
          { seq: 7, ts: "2026-11-18T00:00:00Z", run_id: "M-1", type: "mission.replan" },
          { seq: 8, ts: "2026-11-18T00:00:01Z", run_id: "M-1", type: "task.created", task_id: "T-9" },
        ],
      })}
      missionErr={null}
      findings={[]}
    />);
    expect(screen.getByText("unresolved_verification")).toBeInTheDocument();
    expect(screen.getByText(/mission\.replan/i)).toBeInTheDocument();
    expect(screen.getByText(/task\.created · T-9/i)).toBeInTheDocument();
  });
});

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { LaunchRunPanel } from "./LaunchRunPanel";
import { api, clearApiMocks, navState } from "@/test/mocks";

vi.mock("@/lib/api", async () => {
  const m = await import("@/test/mocks");
  return { api: m.api, errMessage: m.errMessage, ApiError: m.ApiError, reportUrl: m.reportUrl, API_BASE: m.API_BASE };
});
vi.mock("next/navigation", async () => {
  const m = await import("@/test/mocks");
  return m.makeNavigationMock();
});

/** Phase 8: launch form — endpoint selection per driver, provider/model
 *  behavior, plan validation, redirect target. */
describe("LaunchRunPanel", () => {
  beforeEach(() => {
    clearApiMocks();
    navState.search = "";
  });

  it("classic mode posts to /api/runs and redirects to the run page", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.type(screen.getByLabelText(/engagement_path/i), "/eng");
    await user.type(screen.getByLabelText(/objective/i), "do it");
    await user.click(screen.getByRole("button", { name: /^launch run$/i }));
    expect(api.launchRun).toHaveBeenCalledTimes(1);
    expect(api.launchMission).not.toHaveBeenCalled();
    expect(api.launchRun.mock.calls[0][0]).toMatchObject({ engagement_path: "/eng", multi_agent: true });
    expect(navState.push).toHaveBeenCalledWith("/runs?id=R1");
  });

  it("mission mode posts to /api/missions (no multi_agent, no source_dir), redirects the same way", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.click(screen.getByRole("radio", { name: /adaptive mission/i }));
    expect(screen.queryByLabelText(/multi_agent/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^source_dir/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/asset_feed/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText(/engagement_path/i), "/eng");
    await user.type(screen.getByLabelText(/objective/i), "adapt");
    await user.click(screen.getByRole("button", { name: /^launch mission$/i }));
    expect(api.launchMission).toHaveBeenCalledTimes(1);
    const body = api.launchMission.mock.calls[0][0];
    expect(body).toMatchObject({ engagement_path: "/eng" });
    expect(body.plan).toBeUndefined();          // default = dynamic frontier
    expect(api.launchRun).not.toHaveBeenCalled();
    expect(navState.push).toHaveBeenCalledWith("/runs?id=R1");
  });

  it("an explicit mission plan is opt-in and validated as a JSON array", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.click(screen.getByRole("radio", { name: /adaptive mission/i }));
    await user.click(screen.getByRole("button", { name: /explicit plan/i }));
    await user.type(screen.getByLabelText(/plan \(json array\)/i), "plain invalid text");
    await user.type(screen.getByLabelText(/engagement_path/i), "/eng");
    await user.type(screen.getByLabelText(/objective/i), "x");
    await user.click(screen.getByRole("button", { name: /^launch mission$/i }));
    expect(api.launchMission).not.toHaveBeenCalled();
    expect(screen.getByText(/must be a JSON array/i)).toBeInTheDocument();

    // fireEvent for the JSON text: userEvent.type treats "{" as a key modifier
    const planArea = screen.getByLabelText(/plan \(json array\)/i);
    fireEvent.change(planArea, { target: { value: '[{"technique":"sqli","target":"/orders"}]' } });
    await user.click(screen.getByRole("button", { name: /^launch mission$/i }));
    expect(api.launchMission).toHaveBeenCalledTimes(1);
    expect(api.launchMission.mock.calls[0][0].plan).toEqual([
      { technique: "sqli", target: "/orders" },
    ]);
  });

  it("provider change resets the model field (presets are per provider)", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.selectOptions(screen.getByLabelText(/^provider/i), "zai");
    const model = screen.getByLabelText(/^model/i);
    await user.type(model, "glm-5.3");
    expect(model).toHaveValue("glm-5.3");
    await user.selectOptions(screen.getByLabelText(/^provider/i), "openai");
    expect(screen.getByLabelText(/^model/i)).toHaveValue("");     // reset
    expect(screen.queryByDisplayValue("glm-5.3")).not.toBeInTheDocument();
  });

  it("provider/model/key/base_url flow into BOTH drivers' llm override", async () => {
    const user = userEvent.setup();
    // one render per driver: a successful launch leaves the panel in its
    // post-launch state (the real app navigates away), so the mission run
    // goes through a fresh mount with the same form values re-typed.
    render(<LaunchRunPanel />);
    await user.selectOptions(screen.getByLabelText(/^provider/i), "zai");
    await user.type(screen.getByLabelText(/^model/i), "glm-5.3");
    await user.type(screen.getByLabelText(/^api key/i), "sk-run");
    await user.type(screen.getByLabelText(/engagement_path/i), "/eng");
    await user.type(screen.getByLabelText(/objective/i), "x");
    await user.click(screen.getByRole("button", { name: /^launch run$/i }));
    expect(api.launchRun.mock.calls[0][0].llm).toEqual({
      provider: "zai", model: "glm-5.3", api_key: "sk-run",
    });

    cleanup();
    render(<LaunchRunPanel />);
    await user.click(screen.getByRole("radio", { name: /adaptive mission/i }));
    await user.selectOptions(screen.getByLabelText(/^provider/i), "zai");
    await user.type(screen.getByLabelText(/^model/i), "glm-5.3");
    await user.type(screen.getByLabelText(/^api key/i), "sk-run");
    await user.type(screen.getByLabelText(/engagement_path/i), "/eng");
    await user.type(screen.getByLabelText(/objective/i), "x");
    await user.click(screen.getByRole("button", { name: /^launch mission$/i }));
    expect(api.launchMission.mock.calls[0][0].llm).toEqual({
      provider: "zai", model: "glm-5.3", api_key: "sk-run",
    });
  });
});

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
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

/** Builder 04: URL-first launch — no engagement_path anywhere, Ollama
 *  auto-connect with honest states, fail-closed authorization, preflight
 *  gating, scope summary, and the /api/launch contract for BOTH drivers. */
describe("LaunchRunPanel (URL-first)", () => {
  beforeEach(() => {
    clearApiMocks();
    navState.search = "";
  });
  afterEach(() => cleanup());

  /** Fill everything EXCEPT the listed fields, then try to launch. */
  async function fillValidForm(user: ReturnType<typeof userEvent.setup>) {
    const target = screen.getByLabelText(/target url/i);
    const objective = screen.getByPlaceholderText(/Choose an engagement type above/i);
    await user.clear(target);
    await user.type(target, "https://demo.testfire.net");
    await user.clear(objective);
    await user.type(objective, "Assess the authorized web app");
    await user.type(screen.getByLabelText(/^authorized by/i), "Shivakant, security owner");
    await user.type(screen.getByLabelText(/^ticket/i), "ROE-2026-041");
    await user.click(screen.getByLabelText(/confirm authorization/i));
  }

  it("has no engagement_path field — the operator enters a target URL", () => {
    render(<LaunchRunPanel />);
    expect(screen.queryByLabelText(/engagement_path/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/target url/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/confirm authorization/i)).not.toBeChecked();
  });

  it("classic mode posts to /api/launch with fail-closed authorization and redirects", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await fillValidForm(user);
    await user.click(screen.getByRole("button", { name: /^launch run$/i }));
    await waitFor(() => expect(api.launchFromUrl).toHaveBeenCalledTimes(1));
    const body = api.launchFromUrl.mock.calls[0][0];
    expect(body).toMatchObject({
      target_url: "https://demo.testfire.net",
      mode: "classic",
      intensity: "standard",
      max_steps: 40,
    });
    expect(body.authorization).toMatchObject({
      confirmed: true,
      authorized_by: "Shivakant, security owner",
      ticket: "ROE-2026-041",
    });
    expect(body.llm).toMatchObject({ provider: "ollama" });
    expect(api.launchRun).not.toHaveBeenCalled();
    expect(api.launchMission).not.toHaveBeenCalled();
    expect(navState.push).toHaveBeenCalledWith("/runs?id=R1");
  });

  it("mission mode posts mode=mission through the same URL-first endpoint", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.click(screen.getByRole("radio", { name: /adaptive mission/i }));
    await fillValidForm(user);
    await user.click(screen.getByRole("button", { name: /^launch mission$/i }));
    await waitFor(() => expect(api.launchFromUrl).toHaveBeenCalledTimes(1));
    expect(api.launchFromUrl.mock.calls[0][0].mode).toBe("mission");
    expect(navState.push).toHaveBeenCalledWith("/runs?id=R1");
  });

  it("fails closed in the UI: no confirmation checkbox → no POST, actionable error", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.type(screen.getByLabelText(/target url/i), "https://demo.testfire.net");
    await user.type(screen.getByLabelText(/objective/i), "assess");
    await user.type(screen.getByLabelText(/^authorized by/i), "owner");
    await user.type(screen.getByLabelText(/^ticket/i), "ROE-1");
    await user.click(screen.getByRole("button", { name: /^launch run$/i }));
    expect(api.launchFromUrl).not.toHaveBeenCalled();
    expect(await screen.findByText(/authorization confirmation is required/i)).toBeInTheDocument();
  });

  it("missing authorized_by or ticket → actionable error, no POST", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.type(screen.getByLabelText(/target url/i), "https://demo.testfire.net");
    await user.type(screen.getByLabelText(/objective/i), "assess");
    await user.click(screen.getByLabelText(/confirm authorization/i));
    await user.click(screen.getByRole("button", { name: /^launch run$/i }));
    expect(api.launchFromUrl).not.toHaveBeenCalled();
    expect(await screen.findByText(/authorized_by is required/i)).toBeInTheDocument();
    expect(screen.getByText(/ticket is required/i)).toBeInTheDocument();
  });

  it("scheme-less URL gets instant client-side feedback", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.type(screen.getByLabelText(/target url/i), "demo.testfire.net");
    expect(await screen.findByText(/include the scheme/i)).toBeInTheDocument();
  });

  it("shows the exact scope that will be generated before launch", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.type(screen.getByLabelText(/target url/i), "https://demo.testfire.net/login");
    expect(await screen.findByText(/demo\.testfire\.net:443/i)).toBeInTheDocument();
    expect(screen.getByText(/redirects and discovered hosts are re-checked/i)).toBeInTheDocument();
  });

  it("ollama auto-connect: probes on mount, lists installed models, auto-selects the default, runs preflight once", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    expect(await screen.findByText("Ollama connected — 2 models available")).toBeInTheDocument();
    expect(api.ollamaStatus).toHaveBeenCalled();
    const modelInput = screen.getByLabelText(/^model/i) as HTMLInputElement;
    await waitFor(() => expect(modelInput.value).toBe("qwen2.5:7b-instruct"));
    await waitFor(() => expect(api.preflightLlm).toHaveBeenCalledTimes(1));
    expect(api.preflightLlm.mock.calls[0][0]).toMatchObject({
      provider: "ollama",
      model: "qwen2.5:7b-instruct",
    });
    // launch stays enabled once connected + prefighted OK
    await fillValidForm(user);
    expect(screen.getByRole("button", { name: /^launch run$/i })).toBeEnabled();
  });

  it('ollama not running shows "Ollama is not running. Start Ollama and retry." and blocks launch', async () => {
    api.ollamaStatus.mockResolvedValueOnce({
      provider: "ollama", base_url: "http://127.0.0.1:11434", connected: false,
      state: "not_running", version: "", models: [], default_model: "",
      message: "Ollama is not running. Start Ollama and retry.",
    });
    render(<LaunchRunPanel />);
    // the message shows in the status panel AND the launch-blocker list
    expect((await screen.findAllByText("Ollama is not running. Start Ollama and retry.")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("button", { name: /^launch run$/i })).toBeDisabled();
  });

  it("ollama with no models shows the pull-a-model message and blocks launch", async () => {
    api.ollamaStatus.mockResolvedValueOnce({
      provider: "ollama", base_url: "http://127.0.0.1:11434", connected: true,
      state: "no_models", version: "0.6.2", models: [], default_model: "",
      message: "Ollama is running, but no models are installed. Pull a supported model first.",
    });
    render(<LaunchRunPanel />);
    expect((await screen.findAllByText(/no models are installed\. Pull a supported model first\./i)).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("button", { name: /^launch run$/i })).toBeDisabled();
  });

  it("a failed tool-call preflight blocks launch with the exact guidance", async () => {
    api.preflightLlm.mockResolvedValueOnce({
      provider: "ollama", base_url: "http://127.0.0.1:11434/v1", model: "plainmodel:latest",
      reachable: true, model_found: true, tool_call_ok: false, args_parsed: false,
      ok: false, latency_ms: 9, error: "no tool call in response",
      checks: [{ check: "tool_call_ok", ok: false, detail: "model answered in plain text" }],
    });
    render(<LaunchRunPanel />);
    await screen.findByText("Ollama connected — 2 models available");
    await waitFor(() => expect(api.preflightLlm).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/did not pass tool-calling preflight\. Select another model\./i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^launch run$/i })).toBeDisabled();
  });

  it("the scope summary names the local-lab opt-in when private ranges are authorized", async () => {
    const user = userEvent.setup();
    render(<LaunchRunPanel />);
    await user.type(screen.getByLabelText(/target url/i), "http://127.0.0.1:8901/");
    await user.click(screen.getByLabelText(/local \/ private lab target/i));
    expect(await screen.findByText(/127\.0\.0\.1:8901/i)).toBeInTheDocument();
    expect(screen.getByText(/explicitly authorized for this local-lab target/i)).toBeInTheDocument();
  });
});

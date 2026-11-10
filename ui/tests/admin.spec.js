import { expect, test } from "@playwright/test";

async function signIn(page, who) {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in" }).click();
  // Local dev issuer: pick the identity and org membership.
  await page.getByRole("button", { name: new RegExp(`${who}@example\\.test.*Demo Org`) }).click();
  await expect(page.getByTestId("whoami")).toBeVisible();
}

function badgeIn(doorId, badge, people) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:8000/ws/controllers/${doorId}?token=acc_dev_controller`);
    ws.onopen = () => ws.send(JSON.stringify({ type: "badge", badge, req_id: 1, sim_people: people }));
    ws.onmessage = (m) => { ws.close(); resolve(JSON.parse(m.data)); };
    ws.onerror = reject;
  });
}

test("viewer sees doors but no controls", async ({ page }) => {
  await signIn(page, "carol");
  await expect(page.getByTestId("whoami")).toContainText("viewer");
  await expect(page.getByTestId(/^door-/)).toHaveCount(4);
  await expect(page.getByRole("button", { name: "Lock down" })).toHaveCount(0);
});

test("operator lockdown toggles door mode", async ({ page }) => {
  await signIn(page, "bob");
  const dock = page.getByTestId("door-3");
  await dock.getByRole("button", { name: "Lock down" }).click();
  await expect(dock).toContainText("lockdown");
  expect((await badgeIn(3, "1001", 1)).reason).toBe("door_lockdown");
  await dock.getByRole("button", { name: "End lockdown" }).click();
  await expect(dock).toContainText("normal");
});

test("remote unlock needs an operator request and admin approval", async ({ page }) => {
  await signIn(page, "bob");
  page.once("dialog", (d) => d.accept("courier waiting at lobby"));
  await page.getByTestId("door-1").getByRole("button", { name: "Request unlock" }).click();
  await expect(page.getByRole("status")).toContainText("waiting for an admin");
  await page.getByRole("button", { name: "Unlock approvals" }).click();
  await expect(page.getByTestId("unlock-request")).toContainText("courier waiting at lobby");
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0); // operators cannot approve

  await page.getByRole("button", { name: "Sign out" }).click();
  await signIn(page, "alice");
  await page.getByRole("button", { name: "Unlock approvals" }).click();
  await page.getByTestId("unlock-request").filter({ hasText: "courier waiting at lobby" })
    .getByRole("button", { name: "Approve" }).click();
  await expect(page.getByRole("status")).toContainText("approved");
  await expect(page.getByText("No pending unlock requests.")).toBeVisible();
});

test("tailgate shows up in events with its clip", async ({ page }) => {
  const decision = await badgeIn(1, "1001", 2);
  expect(decision.granted).toBe(true);
  await signIn(page, "alice");
  await page.getByRole("button", { name: "Access events" }).click();
  await page.getByRole("button", { name: "Tailgates only" }).click();
  const row = page.getByTestId("event-row").first();
  await expect(row).toContainText("tailgate");
  await row.getByRole("button", { name: "View" }).click();
  await expect(page.getByTestId("clip")).toContainText("max people: 2");
});

import { useCallback, useEffect, useRef, useState } from "react";
import "./App.css";
import Login from "./Login.jsx";
import { fetchReport } from "./api.js";

const TOKEN_KEY = "identityguard.accessToken";
const REPORT_PERMISSION = "IdentityGuard:reports.read";

const navigation = [
  {
    heading: "WORKSPACE",
    items: [
      { id: "overview", label: "Overview", icon: "◫" },
      { id: "identities", label: "Identities", icon: "◎" },
      { id: "access", label: "Access requests", icon: "⇄" },
      { id: "reviews", label: "Access reviews", icon: "☷" },
    ],
  },
  {
    heading: "SECURITY",
    items: [
      { id: "roles", label: "Roles & permissions", icon: "⬡" },
      { id: "pam", label: "Privileged access", icon: "⌑" },
      { id: "audit", label: "Audit trail", icon: "≋" },
      { id: "reports", label: "Reports", icon: "▥" },
    ],
  },
];

const pageLabels = {
  profile: "My profile",
  settings: "Account settings",
};

const searchPlaceholders = {
  overview: "Search audit activity...",
  identities: "Search identities...",
  access: "Search access requests...",
  reviews: "Search access reviews...",
  roles: "Search roles and permissions...",
  pam: "Search privileged access...",
  audit: "Search audit events...",
  reports: "Search reports...",
  profile: "Search profile...",
  settings: "Search settings...",
};

const sectionDescriptions = {
  identities:
    "Identity records will be searchable when the identity data source is connected.",
  access:
    "Access requests will be searchable when the request data source is connected.",
  reviews:
    "Access reviews will be searchable when the review data source is connected.",
  roles:
    "Roles and permissions will be searchable when the authorization data source is connected.",
  pam:
    "Privileged-access records will be searchable when the PAM data source is connected.",
  audit:
    "Audit events will be searchable when the audit data source is connected.",
  reports:
    "Available reports will be searchable when report data is connected.",
  profile: "Your IdentityGuard account details.",
  settings: "Account security and preferences.",
};

const reportEndpoints = [
  ["identities", "/reports/identity-inventory"],
  ["requests", "/reports/access-request-history"],
  ["reviews", "/reports/access-review-summary"],
  ["assignments", "/reports/role-access-assignments"],
  ["audit", "/reports/audit-trail"],
];

function getErrorMessage(error, fallback) {
  return error instanceof Error && error.message
    ? error.message
    : fallback;
}

function formatDateTime(value) {
  if (!value) return "—";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString();
}

function getAuditStatus(item) {
  const result = String(item?.result ?? "").toUpperCase();

  if (result.includes("DENIED") || result.includes("FAIL")) {
    return "Denied";
  }

  if (result === "SUCCESS") {
    return "Success";
  }

  return item?.result || "Recorded";
}

function getAuditTimestamp(item) {
  return (
    item?.created_at ??
    item?.occurred_at ??
    item?.timestamp ??
    item?.event_time ??
    item?.createdAt ??
    null
  );
}

function getReviewCompletion(report) {
  const items = report?.total_review_items ?? 0;
  const pending = report?.pending_decisions ?? 0;

  if (!items) return null;

  return Math.round(((items - pending) / items) * 100);
}

async function accessReviewRequest(path, token, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      Authorization: `Bearer ${token}`,
      ...options.headers,
    },
  });

  const payload = response.status === 204 ? null : await response.json().catch(() => null);

  if (!response.ok) {
    const detail = payload?.detail;
    const message = typeof detail === "string"
      ? detail
      : `Request failed with status ${response.status}.`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return payload;
}

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [search, setSearch] = useState("");
  const [openMenu, setOpenMenu] = useState(null);

  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [sessionLoading, setSessionLoading] = useState(true);

  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState("");

  const [dashboardData, setDashboardData] = useState(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [dashboardError, setDashboardError] = useState("");
  const [sectionData, setSectionData] = useState({});
  const [sectionLoading, setSectionLoading] = useState(false);
  const [sectionError, setSectionError] = useState("");
  const [accessReviewCycles, setAccessReviewCycles] = useState([]);
  const [selectedReviewId, setSelectedReviewId] = useState(null);
  const [selectedReview, setSelectedReview] = useState(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewError, setReviewError] = useState("");
  const [reviewSuccess, setReviewSuccess] = useState("");
  const [newReviewName, setNewReviewName] = useState("");
  const [creatingReview, setCreatingReview] = useState(false);
  const [decisionDrafts, setDecisionDrafts] = useState({});
  const [reviewActionLoading, setReviewActionLoading] = useState(false);

  const sidebarMenuRef = useRef(null);
  const topMenuRef = useRef(null);

  const displayName =
    currentUser?.full_name || currentUser?.username || "User";

  const userRole =
    currentUser?.roles?.join(", ") || "No role assigned";

  const userInitials = displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("");

  const permissions = currentUser?.permissions ?? [];
  const canReadReports = permissions.includes(REPORT_PERMISSION);
  const canCreateReviews = permissions.includes("IdentityGuard:access_review.create");
  const canViewReviews = permissions.includes("IdentityGuard:access_review.view");
  const canDecideReviews = permissions.includes("IdentityGuard:access_review.decide");
  const canCompleteReviews = permissions.includes("IdentityGuard:access_review.complete");

  const normalizedSearch = search.trim().toLowerCase();

  const isOverview = activePage === "overview";
  const isProfilePage =
    activePage === "profile" || activePage === "settings";

  const activeLabel =
    pageLabels[activePage] ??
    navigation
      .flatMap((group) => group.items)
      .find((item) => item.id === activePage)?.label ??
    "Overview";

  const sectionDescription = sectionDescriptions[activePage];

  const identityReport = dashboardData?.identities;
  const requestReport = dashboardData?.requests;
  const reviewReport = dashboardData?.reviews;
  const assignmentReport = dashboardData?.assignments;
  const auditReport = dashboardData?.audit;

  const dashboardStats = [
    {
      label: "Total identities",
      value: identityReport?.total_count ?? "—",
      note: "Across your directory",
      icon: "◎",
      target: "identities",
    },
    {
      label: "Access requests",
      value: requestReport?.requested_count ?? "—",
      note: "Requests submitted",
      icon: "⇄",
      accent: true,
      target: "access",
    },
    {
      label: "Review completion",
      value:
        getReviewCompletion(reviewReport) === null
          ? "—"
          : `${getReviewCompletion(reviewReport)}%`,
      note: "Across review items",
      icon: "☷",
      target: "reviews",
    },
    {
      label: "Privileged assignments",
      value: assignmentReport?.privileged_assignment_count ?? "—",
      note: "Privileged role assignments",
      icon: "⌑",
      target: "pam",
    },
  ];

  const auditItems = auditReport?.items ?? [];

  const filteredActivity = auditItems.filter((item) =>
    [
      item?.actor,
      item?.action,
      item?.event_type,
      item?.target,
      item?.result,
      item?.correlation_id,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(normalizedSearch)
  );

  const reviewCompletion = getReviewCompletion(reviewReport);

  const reviewCycles = reviewReport?.items ?? [];

  const latestReviewCycle = reviewCycles[0] ?? null;

  const reviewCycleName =
    latestReviewCycle?.name || "Access review summary";

  const reviewCycleStatus =
    latestReviewCycle?.status || "No review data";

  const reviewTotal =
    latestReviewCycle?.total_count ??
    reviewReport?.total_review_items ??
    0;

  const reviewPending =
    latestReviewCycle?.pending_count ??
    reviewReport?.pending_decisions ??
    0;

  const reviewDecided = Math.max(0, reviewTotal - reviewPending);

  const reviewPercentage =
    latestReviewCycle?.completion_percentage ??
    reviewCompletion;

  const attentionCount =
    (requestReport?.requested_count ?? 0) +
    (reviewReport?.pending_decisions ?? 0);

  const attentionMessage =
    attentionCount > 0
      ? `${attentionCount} pending request or review item(s) need attention.`
      : "No pending items were reported.";

  const activityEmptyMessage = normalizedSearch
    ? `No audit events match "${search.trim()}".`
    : "No audit events have been recorded yet.";

  const loadDashboard = useCallback(async () => {
    if (!token || !currentUser) return;

    if (!canReadReports) {
      setDashboardData(null);
      setDashboardError(
        "Your account does not have permission to view dashboard reports."
      );
      return;
    }

    setDashboardLoading(true);
    setDashboardError("");

    try {
      const results = await Promise.allSettled(
        reportEndpoints.map(async ([key, path]) => ({
          key,
          data: await fetchReport(path, token),
        }))
      );

      const nextData = {};
      const failures = [];
      let sessionExpired = false;
      let permissionDenied = false;

      for (let index = 0; index < results.length; index += 1) {
        const result = results[index];

        if (result.status === "fulfilled") {
          nextData[result.value.key] = result.value.data;
          continue;
        }

        const error = result.reason;

        if (error?.status === 401) {
          sessionExpired = true;
        } else if (error?.status === 403) {
          permissionDenied = true;
        } else {
          failures.push(
            getErrorMessage(error, "A report could not be loaded.")
          );
        }
      }

      if (sessionExpired) {
        localStorage.removeItem(TOKEN_KEY);
        setToken(null);
        setCurrentUser(null);
        setDashboardData(null);
        setAuthError("Your session expired. Please sign in again.");
        return;
      }

      if (permissionDenied) {
        setDashboardData(nextData);
        setDashboardError(
          "Access to one or more reports was denied. Check your account permissions."
        );
        return;
      }

      setDashboardData(nextData);

      if (failures.length > 0) {
        setDashboardError(
          `${failures.length} report(s) could not be loaded. Available report data is shown.`
        );
      }
    } catch (error) {
      setDashboardError(
        getErrorMessage(error, "Unable to load dashboard reports.")
      );
    } finally {
      setDashboardLoading(false);
    }
  }, [token, currentUser, canReadReports]);

  const loadSection = useCallback(
    async (page) => {
      const endpointByPage = {
        identities: "/reports/identity-inventory",
        access: "/reports/access-request-history",
      };

      const endpoint = endpointByPage[page];

      if (!endpoint || !token || !currentUser) return;

      if (!canReadReports) {
        setSectionData((current) => ({
          ...current,
          [page]: null,
        }));
        setSectionError(
          "Your account does not have permission to view this data."
        );
        return;
      }

      setSectionLoading(true);
      setSectionError("");

      try {
        const data = await fetchReport(endpoint, token);

        setSectionData((current) => ({
          ...current,
          [page]: data,
        }));
      } catch (error) {
        if (error?.status === 401) {
          localStorage.removeItem(TOKEN_KEY);
          setToken(null);
          setCurrentUser(null);
          setDashboardData(null);
          setAuthError("Your session expired. Please sign in again.");
          return;
        }

        setSectionError(
          error?.status === 403
            ? "Your account does not have permission to view this data."
            : getErrorMessage(error, "Unable to load records.")
        );
      } finally {
        setSectionLoading(false);
      }
    },
    [token, currentUser, canReadReports]
  );

  const loadReviews = useCallback(async (preferredCycleId = null) => {
    if (!token || !currentUser || activePage !== "reviews") return;

    if (!canViewReviews) {
      setAccessReviewCycles([]);
      setSelectedReview(null);
      setReviewError("Your account does not have permission to view access reviews.");
      return;
    }

    setReviewLoading(true);
    setReviewError("");
    setReviewSuccess("");

    try {
      const cycles = await accessReviewRequest("/access-reviews", token);
      setAccessReviewCycles(Array.isArray(cycles) ? cycles : []);

      const desiredId = preferredCycleId ?? selectedReviewId ?? cycles?.[0]?.id ?? null;
      if (desiredId !== null) {
        const detail = await accessReviewRequest(`/access-reviews/${desiredId}`, token);
        setSelectedReview(detail);
        setSelectedReviewId(detail.id);
        setDecisionDrafts((current) => {
          const next = { ...current };
          for (const item of detail.items ?? []) {
            if (!next[item.id]) next[item.id] = { decision: "RETAIN", reason: "" };
          }
          return next;
        });
      } else {
        setSelectedReview(null);
        setSelectedReviewId(null);
      }
    } catch (error) {
      if (error?.status === 401) {
        localStorage.removeItem(TOKEN_KEY);
        setToken(null);
        setCurrentUser(null);
        setDashboardData(null);
        setAuthError("Your session expired. Please sign in again.");
        return;
      }
      setReviewError(
        error?.status === 403
          ? "Your account does not have permission to view access reviews."
          : getErrorMessage(error, "Unable to load access review cycles.")
      );
    } finally {
      setReviewLoading(false);
    }
  }, [token, currentUser, activePage, canViewReviews, selectedReviewId]);

  useEffect(() => {
    if (!token || !currentUser || activePage !== "reviews") return;
    const timer = setTimeout(() => { void loadReviews(); }, 0);
    return () => clearTimeout(timer);
  }, [token, currentUser, activePage, loadReviews]);

  async function handleCreateReview(event) {
    event.preventDefault();
    const name = newReviewName.trim();
    if (!name) {
      setReviewError("Enter a name for the access review cycle.");
      return;
    }

    setCreatingReview(true);
    setReviewError("");
    setReviewSuccess("");
    try {
      const cycle = await accessReviewRequest("/access-reviews", token, {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setNewReviewName("");
      setReviewSuccess(`Created review cycle "${cycle.name}".`);
      await loadReviews(cycle.id);
    } catch (error) {
      if (error?.status === 401) {
        localStorage.removeItem(TOKEN_KEY);
        setToken(null);
        setCurrentUser(null);
        setAuthError("Your session expired. Please sign in again.");
        return;
      }
      setReviewError(
        error?.status === 403
          ? "Your account does not have permission to create review cycles."
          : getErrorMessage(error, "Unable to create the review cycle.")
      );
    } finally {
      setCreatingReview(false);
    }
  }

  async function handleReviewDecision(item) {
    if (!selectedReview || !canDecideReviews) return;
    const draft = decisionDrafts[item.id] ?? {};
    const reason = String(draft.reason ?? "").trim();
    if (!reason) {
      setReviewError(`A reason is required for review item ${item.id}.`);
      return;
    }

    setReviewActionLoading(true);
    setReviewError("");
    setReviewSuccess("");
    try {
      await accessReviewRequest(`/access-reviews/${selectedReview.id}/decisions`, token, {
        method: "POST",
        body: JSON.stringify({
          item_id: item.id,
          decision: draft.decision || "RETAIN",
          reason,
        }),
      });
      setReviewSuccess(`Decision recorded for review item ${item.id}.`);
      await loadReviews(selectedReview.id);
    } catch (error) {
      if (error?.status === 401) {
        localStorage.removeItem(TOKEN_KEY);
        setToken(null);
        setCurrentUser(null);
        setAuthError("Your session expired. Please sign in again.");
        return;
      }
      setReviewError(getErrorMessage(error, "Unable to record the review decision."));
    } finally {
      setReviewActionLoading(false);
    }
  }

  async function handleCompleteReview() {
    if (!selectedReview || !canCompleteReviews) return;
    if (!window.confirm("Complete this review cycle? Revoke decisions will remove the corresponding role assignments.")) return;

    setReviewActionLoading(true);
    setReviewError("");
    setReviewSuccess("");
    try {
      const cycle = await accessReviewRequest(`/access-reviews/${selectedReview.id}/complete`, token, {
        method: "POST",
      });
      setReviewSuccess(`Review cycle "${cycle.name}" completed.`);
      await loadReviews(cycle.id);
    } catch (error) {
      if (error?.status === 401) {
        localStorage.removeItem(TOKEN_KEY);
        setToken(null);
        setCurrentUser(null);
        setAuthError("Your session expired. Please sign in again.");
        return;
      }
      setReviewError(getErrorMessage(error, "Unable to complete the review cycle."));
    } finally {
      setReviewActionLoading(false);
    }
  }

  async function handleLogin(credentials) {
    setAuthLoading(true);
    setAuthError("");

    try {
      const loginResponse = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials),
      });

      if (!loginResponse.ok) {
        if (loginResponse.status === 401) {
          throw new Error("Invalid username or password.");
        }

        if (loginResponse.status === 429) {
          throw new Error(
            "Too many attempts. Please wait before trying again."
          );
        }

        throw new Error("Sign-in failed. Please try again.");
      }

      const loginData = await loginResponse.json();

      if (
        typeof loginData.access_token !== "string" ||
        !loginData.access_token
      ) {
        throw new Error("The server did not return a valid access token.");
      }

      const profileResponse = await fetch("/auth/me", {
        headers: {
          Authorization: `Bearer ${loginData.access_token}`,
        },
      });

      if (!profileResponse.ok) {
        throw new Error(
          profileResponse.status === 401
            ? "Your session could not be verified. Please sign in again."
            : profileResponse.status === 403
              ? "You do not have permission to access your profile."
              : "Unable to retrieve your account profile."
        );
      }

      const profile = await profileResponse.json();

      if (!profile.username || profile.status !== "ACTIVE") {
        throw new Error("The account profile is incomplete or inactive.");
      }

      localStorage.setItem(TOKEN_KEY, loginData.access_token);

      setCurrentUser(profile);
      setToken(loginData.access_token);
      setDashboardData(null);
      setDashboardError("");
      setActivePage("overview");
      setSearch("");
      setOpenMenu(null);
    } catch (error) {
      localStorage.removeItem(TOKEN_KEY);
      setCurrentUser(null);
      setToken(null);

      setAuthError(
        error instanceof TypeError
          ? "Cannot reach the server. Check that the backend is running."
          : getErrorMessage(error, "An unexpected sign-in error occurred.")
      );
    } finally {
      setAuthLoading(false);
    }
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_KEY);

    setToken(null);
    setCurrentUser(null);
    setDashboardData(null);
    setDashboardError("");
    setActivePage("overview");
    setSearch("");
    setOpenMenu(null);
    setAuthError("");
  }

  useEffect(() => {
    let cancelled = false;

    async function restoreSession() {
      let savedToken;

      try {
        savedToken = localStorage.getItem(TOKEN_KEY);
      } catch {
        if (!cancelled) {
          setSessionLoading(false);
        }
        return;
      }

      if (!savedToken) {
        if (!cancelled) {
          setSessionLoading(false);
        }
        return;
      }

      try {
        const response = await fetch("/auth/me", {
          headers: {
            Authorization: `Bearer ${savedToken}`,
          },
        });

        if (!response.ok) {
          throw new Error("Session is no longer valid.");
        }

        const profile = await response.json();

        if (!profile.username || profile.status !== "ACTIVE") {
          throw new Error("Account is inactive or invalid.");
        }

        if (!cancelled) {
          setToken(savedToken);
          setCurrentUser(profile);
        }
      } catch {
        localStorage.removeItem(TOKEN_KEY);

        if (!cancelled) {
          setToken(null);
          setCurrentUser(null);
        }
      } finally {
        if (!cancelled) {
          setSessionLoading(false);
        }
      }
    }

    restoreSession();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!token || !currentUser || activePage !== "overview") {
      return;
    }

    const timer = setTimeout(() => {
      void loadDashboard();
    }, 0);

    return () => clearTimeout(timer);
  }, [token, currentUser, activePage, loadDashboard]);

  useEffect(() => {
    if (
      !token ||
      !currentUser ||
      !["identities", "access"].includes(activePage)
    ) {
      return;
    }

    const timer = setTimeout(() => {
      void loadSection(activePage);
    }, 0);

    return () => clearTimeout(timer);
  }, [token, currentUser, activePage, loadSection]);

  useEffect(() => {
    function handleOutsideClick(event) {
      const insideSidebar =
        sidebarMenuRef.current?.contains(event.target);
      const insideTop =
        topMenuRef.current?.contains(event.target);

      if (!insideSidebar && !insideTop) {
        setOpenMenu(null);
      }
    }

    function handleEscape(event) {
      if (event.key === "Escape") {
        setOpenMenu(null);
      }
    }

    document.addEventListener("mousedown", handleOutsideClick);
    document.addEventListener("keydown", handleEscape);

    return () => {
      document.removeEventListener("mousedown", handleOutsideClick);
      document.removeEventListener("keydown", handleEscape);
    };
  }, []);

  function toggleMenu(menuName) {
    setOpenMenu((current) =>
      current === menuName ? null : menuName
    );
  }

  function openProfilePage(page) {
    setActivePage(page);
    setSearch("");
    setOpenMenu(null);
  }

  function navigateTo(page) {
    setActivePage(page);
    setSearch("");
    setOpenMenu(null);
  }

  if (sessionLoading) {
    return (
      <main className="session-loading" role="status">
        Restoring your session...
      </main>
    );
  }

  if (!token || !currentUser) {
    return (
      <Login
        onLogin={handleLogin}
        loading={authLoading}
        error={authError}
      />
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(event) => {
            event.preventDefault();
            navigateTo("overview");
          }}
        >
          <span className="brand-mark">IG</span>
          <span className="brand-name"> IdentityGuard</span>
        </a>

        <div className="workspace-switcher">
          <div className="workspace-avatar">A</div>
          <div className="workspace-copy">
            <strong>IdentityGuard workspace</strong>
            <span>Security administration</span>
          </div>
          <span className="switcher-arrow">⌄</span>
        </div>

        <nav className="navigation">
          {navigation.map((group) => (
            <div className="nav-group" key={group.heading}>
              <p className="nav-heading">{group.heading}</p>

              {group.items.map((item) => (
                <button
                  type="button"
                  key={item.id}
                  className={`nav-item ${
                    activePage === item.id ? "active" : ""
                  }`}
                  onClick={() => navigateTo(item.id)}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="security-note">
            <span className="status-dot" />
            <div>
              <strong>Security status</strong>
              <span>Governance workspace</span>
            </div>
          </div>

          <div className="profile-menu-wrapper" ref={sidebarMenuRef}>
            <button
              type="button"
              className="profile"
              aria-haspopup="menu"
              aria-expanded={openMenu === "sidebar"}
              onClick={() => toggleMenu("sidebar")}
            >
              <div className="profile-avatar">{userInitials}</div>
              <div className="profile-copy">
                <strong>{displayName}</strong>
                <span>{userRole}</span>
              </div>
              <span className="switcher-arrow">···</span>
            </button>

            {openMenu === "sidebar" && (
              <div
                className="profile-dropdown sidebar-dropdown"
                role="menu"
              >
                <div className="dropdown-heading">
                  <strong>{displayName}</strong>
                  <span>{userRole}</span>
                </div>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => openProfilePage("profile")}
                >
                  <span>◎</span> My profile
                </button>

                <button
                  type="button"
                  role="menuitem"
                  onClick={() => openProfilePage("settings")}
                >
                  <span>⚙</span> Account settings
                </button>

                <div className="dropdown-divider" />

                <button
                  type="button"
                  role="menuitem"
                  onClick={handleLogout}
                >
                  <span>↪</span> Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{activeLabel}</strong>
          </div>

          <div className="topbar-actions">
            <label className="search-box">
              <span>⌕</span>
              <input
                aria-label={searchPlaceholders[activePage] || "Search"}
                placeholder={
                  searchPlaceholders[activePage] || "Search..."
                }
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />

              {search && (
                <button
                  type="button"
                  className="search-clear"
                  aria-label="Clear search"
                  onClick={() => setSearch("")}
                >
                  ×
                </button>
              )}

              {!search && <kbd>/</kbd>}
            </label>

            <button
              type="button"
              className="icon-button"
              aria-label="Notifications"
              title="Notifications are not connected yet"
            >
              ♧<i />
            </button>

            <div className="top-profile-wrapper" ref={topMenuRef}>
              <button
                type="button"
                className="top-avatar top-avatar-button"
                aria-label="Open user menu"
                aria-haspopup="menu"
                aria-expanded={openMenu === "top"}
                onClick={() => toggleMenu("top")}
              >
                {userInitials}
              </button>

              {openMenu === "top" && (
                <div
                  className="profile-dropdown top-dropdown"
                  role="menu"
                >
                  <div className="dropdown-heading">
                    <strong>{displayName}</strong>
                    <span>{userRole}</span>
                  </div>

                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => openProfilePage("profile")}
                  >
                    <span>◎</span> My profile
                  </button>

                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => openProfilePage("settings")}
                  >
                    <span>⚙</span> Account settings
                  </button>

                  <div className="dropdown-divider" />

                  <button
                    type="button"
                    role="menuitem"
                    onClick={handleLogout}
                  >
                    <span>↪</span> Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <div className="page-content">
          <section className="welcome-row">
            <div>
              <div className="eyebrow">
                <span className="status-dot" />
                IDENTITY GOVERNANCE
              </div>

              <h1>
                {isOverview
                  ? `Welcome, ${displayName}.`
                  : activeLabel}
              </h1>

              <p className="page-subtitle">
                {isOverview
                  ? "A clear view of identity, access and what needs your attention."
                  : sectionDescription ||
                    `Your ${activeLabel.toLowerCase()} workspace.`}
              </p>
            </div>

            {!isProfilePage && (
              <button
                type="button"
                className="primary-button"
                onClick={() => navigateTo("access")}
              >
                <span>＋</span> New access request
              </button>
            )}
          </section>

          {isOverview ? (
            <>
              {!canReadReports ? (
                <section className="panel placeholder-panel">
                  <div className="placeholder-icon">▥</div>
                  <h2>Dashboard reports unavailable</h2>
                  <p>
                    Your account does not have permission to view
                    dashboard reports. Contact an administrator if
                    this access is required.
                  </p>
                </section>
              ) : (
                <>
                  {dashboardError && (
                    <p className="empty-state" role="status">
                      {dashboardError}
                    </p>
                  )}

                  <section
                    className="stats-grid"
                    aria-label="Identity overview"
                    aria-busy={dashboardLoading}
                  >
                    {dashboardStats.map((stat, index) => (
                      <button
                        type="button"
                        className={`stat-card ${
                          stat.accent ? "stat-highlight" : ""
                        }`}
                        key={stat.label}
                        onClick={() => navigateTo(stat.target)}
                      >
                        <div className="stat-top">
                          <span>{stat.label}</span>
                          <span className="stat-icon">{stat.icon}</span>
                        </div>

                        <div className="stat-value">
                          {dashboardLoading && stat.value === "—"
                            ? "…"
                            : stat.value}
                        </div>

                        <div className="stat-note">
                          <span
                            className={
                              index === 1 &&
                              Number(stat.value) > 0
                                ? "note-dot warning"
                                : "note-dot"
                            }
                          />
                          {stat.note}
                        </div>
                      </button>
                    ))}
                  </section>

                  <section className="attention-card">
                    <div className="attention-symbol">!</div>

                    <div className="attention-copy">
                      <strong>
                        {dashboardLoading
                          ? "Loading items that need attention"
                          : attentionCount > 0
                            ? "Items need your attention"
                            : "Attention summary"}
                      </strong>
                      <p>
                        {dashboardLoading
                          ? "Dashboard report data is being retrieved."
                          : attentionMessage}
                      </p>
                    </div>

                    <button
                      type="button"
                      className="text-button"
                      onClick={() => navigateTo("access")}
                    >
                      Review items <span>↗</span>
                    </button>
                  </section>

                  <section className="content-grid">
                    <article className="panel activity-panel">
                      <div className="panel-header">
                        <div>
                          <h2>Recent activity</h2>
                          <p>
                            Audit events recorded by IdentityGuard
                          </p>
                        </div>

                        <button
                          type="button"
                          className="subtle-button"
                          onClick={() => navigateTo("audit")}
                        >
                          View audit trail <span>↗</span>
                        </button>
                      </div>

                      <div className="activity-table">
                        <div className="table-heading">
                          <span>ACTIVITY</span>
                          <span>RESULT</span>
                          <span>TIME</span>
                        </div>

                        {dashboardLoading && (
                          <p className="empty-state" role="status">
                            Loading audit events...
                          </p>
                        )}

                        {!dashboardLoading &&
                          filteredActivity.map((item, index) => {
                            const actor = item.actor || "System";

                            const initials = actor
                              .split(/[\s@._-]+/)
                              .filter(Boolean)
                              .slice(0, 2)
                              .map((part) => part[0].toUpperCase())
                              .join("");

                            const status = getAuditStatus(item);
                            const timestamp = getAuditTimestamp(item);

                            return (
                              <div
                                className="activity-row"
                                key={
                                  item.id ??
                                  item.event_id ??
                                  `${actor}-${item.event_type}-${timestamp}-${index}`
                                }
                              >
                                <div className="activity-person">
                                  <div className="person-avatar">
                                    {initials || "SY"}
                                  </div>

                                  <div className="activity-description">
                                    <strong>{actor}</strong>
                                    <span>
                                      {item.action ||
                                        item.event_type ||
                                        "Audit event"}
                                    </span>
                                    <small>
                                      {item.target ||
                                        "No target recorded"}
                                    </small>
                                  </div>
                                </div>

                                <div>
                                  <span
                                    className={`status-pill ${String(
                                      status
                                    ).toLowerCase()}`}
                                  >
                                    {status}
                                  </span>
                                </div>

                                <time>
                                  {formatDateTime(timestamp)}
                                </time>
                              </div>
                            );
                          })}

                        {!dashboardLoading &&
                          filteredActivity.length === 0 && (
                            <p className="empty-state" role="status">
                              {activityEmptyMessage}
                            </p>
                          )}
                      </div>
                    </article>

                    <article className="panel review-panel">
                      <div className="panel-header">
                        <div>
                          <h2>Access certification</h2>
                          <p>Access review summary</p>
                        </div>
                        <span className="round-arrow">↗</span>
                      </div>

                      <div className="review-progress">
                        <div className="progress-ring">
                          <div>
                            <strong>
                              {reviewPercentage === null ||
                              reviewPercentage === undefined
                                ? "—"
                                : `${Math.round(
                                    Number(reviewPercentage)
                                  )}`}
                              {reviewPercentage !== null &&
                                reviewPercentage !== undefined && (
                                  <span>%</span>
                                )}
                            </strong>
                            <small>complete</small>
                          </div>
                        </div>

                        <div className="review-summary">
                          <strong>{reviewCycleName}</strong>
                          <span>{reviewCycleStatus}</span>
                          <p>
                            {reviewTotal > 0
                              ? `${reviewDecided} of ${reviewTotal} decisions recorded`
                              : "No review data available"}
                          </p>
                        </div>
                      </div>

                      <div className="progress-track">
                        <span
                          style={{
                            width: `${
                              reviewPercentage === null ||
                              reviewPercentage === undefined
                                ? 0
                                : Math.min(
                                    100,
                                    Math.max(
                                      0,
                                      Number(reviewPercentage)
                                    )
                                  )
                            }%`,
                          }}
                        />
                      </div>

                      <div className="review-footer">
                        <span>
                          {reviewTotal > 0
                            ? `${reviewPending} decisions remaining`
                            : "No pending review data"}
                        </span>
                        <button
                          type="button"
                          onClick={() => navigateTo("reviews")}
                        >
                          Open reviews →
                        </button>
                      </div>

                      <div className="review-divider" />

                      <div className="mini-insight">
                        <span className="insight-icon">↗</span>
                        <div>
                          <strong>Keep access intentional.</strong>
                          <p>
                            Review access regularly and remove what is
                            no longer needed.
                          </p>
                        </div>
                      </div>
                    </article>
                  </section>
                </>
              )}

              <footer className="page-footer">
                <span>
                  <span className="footer-mark">IG</span> IdentityGuard
                  <span className="footer-separator">·</span>
                  Identity. Access. Control.
                </span>
                <span>Governance at a glance</span>
              </footer>
            </>
          ) : activePage === "profile" ? (
            <section className="panel placeholder-panel profile-details-panel">
              <div className="placeholder-icon">◎</div>
              <h2>My profile</h2>
              <p>
                Administrator account details for this IdentityGuard
                workspace.
              </p>

              <div className="profile-details">
                <div>
                  <span>Username</span>
                  <strong>{currentUser.username}</strong>
                </div>
                <div>
                  <span>Employee ID</span>
                  <strong>{currentUser.employee_id ?? "Not assigned"}</strong>
                </div>
                <div>
                  <span>Department ID</span>
                  <strong>
                    {currentUser.department_id ?? "Not assigned"}
                  </strong>
                </div>
                <div>
                  <span>Account status</span>
                  <strong>{currentUser.status}</strong>
                </div>
                <div>
                  <span>Assigned roles</span>
                  <strong>{userRole}</strong>
                </div>
              </div>

              <button
                type="button"
                className="primary-button"
                onClick={() => navigateTo("overview")}
              >
                Back to overview
              </button>
            </section>
          ) : activePage === "settings" ? (
            <section className="panel placeholder-panel profile-details-panel">
              <div className="placeholder-icon">⚙</div>
              <h2>Account settings</h2>
              <p>
                Account security and preferences will be configured here.
              </p>

              <div className="profile-details">
                <div>
                  <span>Multi-factor authentication</span>
                  <strong>Planned for Phase 3</strong>
                </div>
                <div>
                  <span>Session management</span>
                  <strong>
                    Session restore and sign out implemented
                  </strong>
                </div>
                <div>
                  <span>Single sign-on</span>
                  <strong>Planned for Phase 5</strong>
                </div>
              </div>

              <button
                type="button"
                className="primary-button"
                onClick={() => navigateTo("overview")}
              >
                Back to overview
              </button>
            </section>

          ) : activePage === "reviews" ? (
            <section className="panel access-reviews-panel">
              <div className="panel-header">
                <div>
                  <h2>Access review governance</h2>
                  <p>Review role assignments, record decisions, and complete certification cycles.</p>
                </div>
                <span className="development-tag">{reviewCycles.length} CYCLE{reviewCycles.length === 1 ? "" : "S"}</span>
              </div>

              {reviewError && <p className="empty-state" role="alert">{reviewError}</p>}
              {reviewSuccess && <p className="review-success" role="status">{reviewSuccess}</p>}

              {canCreateReviews && (
                <form className="review-create-form" onSubmit={handleCreateReview}>
                  <label htmlFor="new-review-name">Create review cycle</label>
                  <div className="review-create-controls">
                    <input
                      id="new-review-name"
                      value={newReviewName}
                      onChange={(event) => setNewReviewName(event.target.value)}
                      maxLength={150}
                      placeholder="e.g. Quarterly Access Review"
                      disabled={creatingReview}
                    />
                    <button className="primary-button" type="submit" disabled={creatingReview || !newReviewName.trim()}>
                      {creatingReview ? "Creating..." : "＋ Create cycle"}
                    </button>
                  </div>
                </form>
              )}

              {!canViewReviews ? (
                <div className="empty-state">Ask an administrator for access-review viewing permission.</div>
              ) : reviewLoading && reviewCycles.length === 0 ? (
                <p className="empty-state" role="status">Loading review cycles...</p>
              ) : (
                <>
                  <div className="review-cycle-list">
                    <label htmlFor="review-cycle-select">Review cycle</label>
                    <select
                      id="review-cycle-select"
                      value={selectedReviewId ?? ""}
                      onChange={(event) => {
                        const id = event.target.value ? Number(event.target.value) : null;
                        setSelectedReviewId(id);
                        if (id !== null) void loadReviews(id);
                      }}
                      disabled={reviewLoading || reviewCycles.length === 0}
                    >
                      {accessReviewCycles.length === 0 && <option value="">No review cycles yet</option>}
                      {accessReviewCycles.map((cycle) => (
                        <option key={cycle.id} value={cycle.id}>
                          {cycle.name} · {cycle.status}
                        </option>
                      ))}
                    </select>
                    <button type="button" className="subtle-button" onClick={() => void loadReviews(selectedReviewId)} disabled={reviewLoading}>
                      {reviewLoading ? "Refreshing..." : "Refresh"}
                    </button>
                  </div>

                  {selectedReview ? (
                    <>
                      <div className="review-cycle-summary">
                        <div><span>Cycle</span><strong>{selectedReview.name}</strong></div>
                        <div><span>Status</span><strong><span className={`status-pill ${String(selectedReview.status).toLowerCase()}`}>{selectedReview.status}</span></strong></div>
                        <div><span>Assignments</span><strong>{selectedReview.items?.length ?? 0}</strong></div>
                        <div><span>Pending decisions</span><strong>{(selectedReview.items ?? []).filter((item) => item.decision === "PENDING").length}</strong></div>
                      </div>

                      <div className="activity-table review-items-table">
                        <div className="table-heading">
                          <span>ASSIGNMENT</span><span>DECISION</span><span>REVIEW</span>
                        </div>
                        {(selectedReview.items ?? []).filter((item) => [
                          item.id, item.user_id, item.role_id, item.decision, item.decision_reason,
                        ].some((value) => String(value ?? "").toLowerCase().includes(normalizedSearch))).map((item) => {
                          const draft = decisionDrafts[item.id] ?? { decision: "RETAIN", reason: "" };
                          const pending = item.decision === "PENDING";
                          return (
                            <div className="activity-row review-item-row" key={item.id}>
                              <div className="activity-description">
                                <strong>Review item #{item.id}</strong>
                                <span>User ID {item.user_id} · Role ID {item.role_id}</span>
                                <small>Assignment recorded {formatDateTime(item.assignment_assigned_at)}</small>
                                {item.decision_reason && <small>Reason: {item.decision_reason}</small>}
                              </div>
                              <div>
                                <span className={`status-pill ${String(item.decision).toLowerCase()}`}>{item.decision}</span>
                                {pending && selectedReview.status === "OPEN" && canDecideReviews && (
                                  <div className="review-decision-controls">
                                    <select
                                      aria-label={`Decision for item ${item.id}`}
                                      value={draft.decision}
                                      onChange={(event) => setDecisionDrafts((current) => ({
                                        ...current,
                                        [item.id]: { ...draft, decision: event.target.value },
                                      }))}
                                      disabled={reviewActionLoading}
                                    >
                                      <option value="RETAIN">Retain access</option>
                                      <option value="REVOKE">Revoke access</option>
                                    </select>
                                    <textarea
                                      aria-label={`Reason for item ${item.id}`}
                                      value={draft.reason}
                                      onChange={(event) => setDecisionDrafts((current) => ({
                                        ...current,
                                        [item.id]: { ...draft, reason: event.target.value },
                                      }))}
                                      maxLength={500}
                                      placeholder="Required reason for this decision"
                                      rows={2}
                                      disabled={reviewActionLoading}
                                    />
                                    <button type="button" className="subtle-button" onClick={() => void handleReviewDecision(item)} disabled={reviewActionLoading || !draft.reason.trim()}>
                                      Record decision
                                    </button>
                                  </div>
                                )}
                              </div>
                              <time>{formatDateTime(item.decided_at)}</time>
                            </div>
                          );
                        })}
                        {(selectedReview.items ?? []).filter((item) => [
                          item.id, item.user_id, item.role_id, item.decision, item.decision_reason,
                        ].some((value) => String(value ?? "").toLowerCase().includes(normalizedSearch))).length === 0 && (
                          <p className="empty-state" role="status">
                            {normalizedSearch ? "No review items match your search." : "This review cycle has no assignment items."}
                          </p>
                        )}
                      </div>

                      {selectedReview.status === "OPEN" && canCompleteReviews && (
                        <div className="review-complete-row">
                          <p>Completing the cycle applies recorded revocation decisions. All items must have a decision first.</p>
                          <button type="button" className="primary-button" onClick={() => void handleCompleteReview()} disabled={reviewActionLoading || (selectedReview.items ?? []).some((item) => item.decision === "PENDING")}>
                            {reviewActionLoading ? "Processing..." : "Complete review cycle"}
                          </button>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="empty-state">
                      {reviewCycles.length === 0
                        ? "No review cycles exist yet. Create one to snapshot current active role assignments."
                        : "Select a review cycle to inspect its assignment snapshot."}
                    </div>
                  )}
                </>
              )}
            </section>
          ) : activePage === "identities" ? (
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Identity inventory</h2>
                  <p>Directory identities and their current status</p>
                </div>
                <span className="development-tag">
                  {sectionData.identities?.total_count ?? 0} RECORDS
                </span>
              </div>

              {sectionError && (
                <p className="empty-state" role="alert">
                  {sectionError}
                </p>
              )}

              {sectionLoading ? (
                <p className="empty-state" role="status">
                  Loading identities...
                </p>
              ) : (
                <>
                  <div className="search-status">
                    <label htmlFor="identity-search">
                      Search identities
                    </label>
                    <input
                      id="identity-search"
                      type="search"
                      placeholder="Username, name, department or status"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                    />
                  </div>

                  <div className="activity-table">
                    <div className="table-heading">
                      <span>IDENTITY</span>
                      <span>DEPARTMENT</span>
                      <span>STATUS</span>
                    </div>

                    {(sectionData.identities?.items ?? [])
                      .filter((item) =>
                        [
                          item.username,
                          item.full_name,
                          item.employee_id,
                          item.department,
                          item.status,
                        ]
                          .filter(Boolean)
                          .join(" ")
                          .toLowerCase()
                          .includes(normalizedSearch)
                      )
                      .map((item) => (
                        <div className="activity-row" key={item.user_id}>
                          <div className="activity-description">
                            <strong>{item.full_name || item.username}</strong>
                            <span>{item.username}</span>
                            <small>
                              {item.employee_id || "No employee ID"}
                            </small>
                          </div>

                          <span>{item.department || "—"}</span>

                          <span
                            className={`status-pill ${String(
                              item.status || "unknown"
                            ).toLowerCase()}`}
                          >
                            {item.status || "Unknown"}
                          </span>
                        </div>
                      ))}

                    {!sectionError &&
                      (sectionData.identities?.items ?? []).filter((item) =>
                        [
                          item.username,
                          item.full_name,
                          item.employee_id,
                          item.department,
                          item.status,
                        ]
                          .filter(Boolean)
                          .join(" ")
                          .toLowerCase()
                          .includes(normalizedSearch)
                      ).length === 0 && (
                        <p className="empty-state" role="status">
                          {normalizedSearch
                            ? "No identities match your search."
                            : "No identity records are available."}
                        </p>
                      )}
                  </div>
                </>
              )}
            </section>
          ) : activePage === "access" ? (
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Access requests</h2>
                  <p>Request history and approval status</p>
                </div>
                <span className="development-tag">
                  {sectionData.access?.total_count ?? 0} RECORDS
                </span>
              </div>

              {sectionError && (
                <p className="empty-state" role="alert">
                  {sectionError}
                </p>
              )}

              {sectionLoading ? (
                <p className="empty-state" role="status">
                  Loading access requests...
                </p>
              ) : (
                <>
                  <div className="search-status">
                    <label htmlFor="access-search">
                      Search access requests
                    </label>
                    <input
                      id="access-search"
                      type="search"
                      placeholder="Requester, target, role or status"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                    />
                  </div>

                  <div className="activity-table">
                    <div className="table-heading">
                      <span>REQUEST</span>
                      <span>STATUS</span>
                      <span>REQUESTED</span>
                    </div>

                    {(sectionData.access?.items ?? [])
                      .filter((item) =>
                        [
                          item.requester_username,
                          item.target_username,
                          item.role_name,
                          item.status,
                          item.justification,
                        ]
                          .filter(Boolean)
                          .join(" ")
                          .toLowerCase()
                          .includes(normalizedSearch)
                      )
                      .map((item) => (
                        <div
                          className="activity-row"
                          key={item.request_id}
                        >
                          <div className="activity-description">
                            <strong>{item.role_name || "Role request"}</strong>
                            <span>
                              {item.requester_username || "Unknown requester"}
                              {" → "}
                              {item.target_username || "Unknown target"}
                            </span>
                            <small>
                              {item.justification || "No justification recorded"}
                            </small>
                          </div>

                          <span
                            className={`status-pill ${String(
                              item.status || "unknown"
                            ).toLowerCase()}`}
                          >
                            {item.status || "Unknown"}
                          </span>

                          <time>{formatDateTime(item.requested_at)}</time>
                        </div>
                      ))}

                    {!sectionError &&
                      (sectionData.access?.items ?? []).filter((item) =>
                        [
                          item.requester_username,
                          item.target_username,
                          item.role_name,
                          item.status,
                          item.justification,
                        ]
                          .filter(Boolean)
                          .join(" ")
                          .toLowerCase()
                          .includes(normalizedSearch)
                      ).length === 0 && (
                        <p className="empty-state" role="status">
                          {normalizedSearch
                            ? "No access requests match your search."
                            : "No access requests are available."}
                        </p>
                      )}
                  </div>
                </>
              )}
            </section>
          ) : (
            <section className="panel placeholder-panel">
              <div className="placeholder-icon">◇</div>
              <h2>{activeLabel}</h2>

              <p>
                {sectionDescription ||
                  "This section is ready for integration with the IdentityGuard API."}
              </p>

              {activePage === "reports" && !canReadReports ? (
                <p role="status">
                  Your account does not have permission to view reports.
                </p>
              ) : normalizedSearch ? (
                <div className="search-status" role="status">
                  <strong>Search is ready for this section</strong>
                  <p>
                    Search term: <span>{search.trim()}</span>
                  </p>
                  <p>
                    Results will appear when this section's records are
                    connected. No records have been searched yet.
                  </p>
                  <button
                    type="button"
                    className="subtle-button"
                    onClick={() => setSearch("")}
                  >
                    Clear search
                  </button>
                </div>
              ) : (
                <span className="development-tag">
                  FRONTEND FOUNDATION
                </span>
              )}

              <button
                type="button"
                className="primary-button"
                onClick={() => navigateTo("overview")}
              >
                Back to overview
              </button>
            </section>
                    )}
        </div>
      </main>
    </div>
  );
}

export default App;
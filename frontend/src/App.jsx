import { useEffect, useRef, useState } from "react";
import "./App.css";
import Login from "./Login.jsx";

const navigation = [
  {
    heading: "WORKSPACE",
    items: [
      { id: "overview", label: "Overview", icon: "◫" },
      { id: "identities", label: "Identities", icon: "◎" },
      { id: "access", label: "Access requests", icon: "⇄", count: "4" },
      { id: "reviews", label: "Access reviews", icon: "☷", count: "2" },
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

const stats = [
  {
    label: "Total identities",
    value: "1,284",
    note: "Across your directory",
    icon: "◎",
    target: "identities",
  },
  {
    label: "Access requests",
    value: "04",
    note: "Awaiting a decision",
    icon: "⇄",
    accent: true,
    target: "access",
  },
  {
    label: "Review completion",
    value: "78%",
    note: "Current review cycle",
    icon: "☷",
    target: "reviews",
  },
  {
    label: "Privileged accounts",
    value: "36",
    note: "Time-bound access",
    icon: "⌑",
    target: "pam",
  },
];

const activity = [
  {
    initials: "PN",
    name: "Priya Nair",
    action: "Requested privileged access",
    target: "Production database",
    time: "10:42 AM",
    status: "Pending",
  },
  {
    initials: "RM",
    name: "Rahul Mehta",
    action: "Role assignment updated",
    target: "Security Analyst",
    time: "10:18 AM",
    status: "Approved",
  },
  {
    initials: "SR",
    name: "Sneha Rao",
    action: "Access review completed",
    target: "Finance applications",
    time: "09:54 AM",
    status: "Completed",
  },
  {
    initials: "MI",
    name: "Meera Iyer",
    action: "Identity profile updated",
    target: "User directory",
    time: "09:21 AM",
    status: "Completed",
  },
];

const pageLabels = {
  profile: "My profile",
  settings: "Account settings",
};

const searchPlaceholders = {
  overview: "Search activity...",
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
  profile:
    "Administrator account details for this IdentityGuard workspace.",
  settings:
    "Account security and preferences will be configured here.",
};

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [search, setSearch] = useState("");
  const [openMenu, setOpenMenu] = useState(null);
  const [token, setToken] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);

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
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState("");

  const sidebarMenuRef = useRef(null);
  const topMenuRef = useRef(null);

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
          : "Unable to retrieve your account profile."
      );
    }

    const profile = await profileResponse.json();

    if (!profile.username || profile.status !== "ACTIVE") {
      throw new Error("The account profile is incomplete or inactive.");
    }

    setCurrentUser(profile);
    setToken(loginData.access_token);
    setActivePage("overview");
    setSearch("");
    setOpenMenu(null);
  } catch (error) {
    setCurrentUser(null);
    setToken(null);
    setAuthError(
      error instanceof TypeError
        ? "Cannot reach the server. Check that the backend is running."
        : error.message || "An unexpected sign-in error occurred."
    );
  } finally {
    setAuthLoading(false);
  }
}

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
  }

  const activeLabel =
    pageLabels[activePage] ??
    navigation
      .flatMap((group) => group.items)
      .find((item) => item.id === activePage)?.label ??
    "Overview";

  const normalizedSearch = search.trim().toLowerCase();

  const filteredActivity = activity.filter((item) =>
    `${item.name} ${item.action} ${item.target} ${item.status} ${item.time}`
      .toLowerCase()
      .includes(normalizedSearch)
  );

  const isOverview = activePage === "overview";
  const isProfilePage =
    activePage === "profile" || activePage === "settings";
  const sectionDescription = sectionDescriptions[activePage];

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
            <strong>Acme workspace</strong>
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
                  {item.count && (
                    <span className="nav-count">{item.count}</span>
                  )}
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

          <div
            className="profile-menu-wrapper"
            ref={sidebarMenuRef}
          >
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
                  className="disabled-menu-item"
                  disabled
                  title="Available after authentication is implemented"
                >
                  <span>↪</span> Sign out
                  <small>Coming soon</small>
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

            <div
              className="top-profile-wrapper"
              ref={topMenuRef}
            >
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
                    className="disabled-menu-item"
                    disabled
                    title="Available after authentication is implemented"
                  >
                    <span>↪</span> Sign out
                    <small>Coming soon</small>
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
                {isOverview ? "Good morning, Admin." : activeLabel}
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
              <section
                className="stats-grid"
                aria-label="Identity overview"
              >
                {stats.map((stat, index) => (
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

                    <div className="stat-value">{stat.value}</div>

                    <div className="stat-note">
                      <span
                        className={
                          index === 1
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
                  <strong>A few things need your attention</strong>
                  <p>
                    Review pending access requests and complete the
                    current certification cycle.
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
                      <p>Changes across your identity environment</p>
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
                      <span>STATUS</span>
                      <span>TIME</span>
                    </div>

                    {filteredActivity.map((item) => (
                      <div
                        className="activity-row"
                        key={`${item.name}-${item.time}`}
                      >
                        <div className="activity-person">
                          <div className="person-avatar">
                            {item.initials}
                          </div>

                          <div className="activity-description">
                            <strong>{item.name}</strong>
                            <span>{item.action}</span>
                            <small>{item.target}</small>
                          </div>
                        </div>

                        <div>
                          <span
                            className={`status-pill ${item.status.toLowerCase()}`}
                          >
                            {item.status}
                          </span>
                        </div>

                        <time>{item.time}</time>
                      </div>
                    ))}

                    {filteredActivity.length === 0 && (
                      <p className="empty-state" role="status">
                        {normalizedSearch
                          ? `No activity matches "${search.trim()}".`
                          : "No activity to display."}
                      </p>
                    )}
                  </div>
                </article>

                <article className="panel review-panel">
                  <div className="panel-header">
                    <div>
                      <h2>Access certification</h2>
                      <p>Quarterly review cycle</p>
                    </div>
                    <span className="round-arrow">↗</span>
                  </div>

                  <div className="review-progress">
                    <div className="progress-ring">
                      <div>
                        <strong>78<span>%</span></strong>
                        <small>complete</small>
                      </div>
                    </div>

                    <div className="review-summary">
                      <strong>Q4 access review</strong>
                      <span>In progress</span>
                      <p>156 of 200 decisions recorded</p>
                    </div>
                  </div>

                  <div className="progress-track">
                    <span />
                  </div>

                  <div className="review-footer">
                    <span>44 decisions remaining</span>
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
                        Review access regularly and remove what is no
                        longer needed.
                      </p>
                    </div>
                  </div>
                </article>
              </section>

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
                  <strong>{currentUser.employee_id}</strong>
                </div>
                <div>
                  <span>Department ID</span>
                  <strong>{currentUser.department_id ?? "Not assigned"}</strong>
                </div>
                <div>
                  <span>Account status</span>
                  <strong>{currentUser.status}</strong>
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
                  <strong>Planned for Phase 2</strong>
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
          ) : (
            <section className="panel placeholder-panel">
              <div className="placeholder-icon">◇</div>
              <h2>{activeLabel}</h2>

              <p>
                {sectionDescription ||
                  "This section is ready for integration with the IdentityGuard API."}
              </p>

              {normalizedSearch ? (
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
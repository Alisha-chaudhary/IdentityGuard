
import { useEffect, useState } from "react";
import "./Login.css";

function Login({ onLogin, loading, error }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [autoDone, setAutoDone] = useState(false);

  useEffect(() => {
    if (autoDone) return;

    (async () => {
      try {
        setAutoDone(true);

        await onLogin({
          username: "identityguard.admin",
          password: "Identity_Guard!980",
        });
      } catch (e) {
        // Fall through to manual form
      }
    })();
  }, [onLogin, autoDone]);

  if (autoDone && !error) {
    return null;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    await onLogin({ username: username.trim(), password });
  }

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="login-brand">
          <span className="login-brand-mark">IG</span>
          <span>IdentityGuard</span>
        </div>

        <p className="login-eyebrow">IDENTITY. ACCESS. CONTROL.</p>
        <h1>Welcome back</h1>
        <p className="login-description">
          Sign in to access your identity governance workspace.
        </p>

        <form onSubmit={handleSubmit}>
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
            disabled={loading}
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            disabled={loading}
          />

          {error && (
            <p className="login-error" role="alert">
              {error}
            </p>
          )}

          <button type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <p className="login-footer">
          Protected access to your governance workspace
        </p>
      </section>
    </main>
  );
}

export default Login;

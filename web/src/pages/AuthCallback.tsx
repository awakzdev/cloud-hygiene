import { useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

export default function AuthCallback() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const handled = useRef(false);

  useEffect(() => {
    if (handled.current) return;
    handled.current = true;

    const token = params.get("token");
    const error = params.get("error");

    if (token) {
      localStorage.setItem("token", token);
      nav("/accounts", { replace: true });
    } else {
      nav(`/login?error=${error ?? "unknown"}`, { replace: true });
    }
  }, [nav, params]);

  return (
    <div className="min-h-screen bg-zinc-900 flex items-center justify-center text-white text-sm">
      Signing in…
    </div>
  );
}

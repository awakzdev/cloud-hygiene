import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { token } from "./api";

const navItem = ({ isActive }: { isActive: boolean }) =>
  `flex items-center gap-2.5 px-2.5 py-1.5 rounded text-[13px] font-medium transition-colors ${
    isActive ? "bg-zinc-800 text-zinc-50" : "text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/50"
  }`;

export default function Layout() {
  const nav = useNavigate();
  useEffect(() => {
    if (!token()) nav("/login");
  }, [nav]);

  return (
    <div className="flex min-h-screen bg-zinc-50 text-zinc-900">
      <aside className="w-52 flex-shrink-0 bg-zinc-950 border-r border-zinc-900 flex flex-col">
        <div className="px-4 py-4 border-b border-zinc-900">
          <div className="flex items-center gap-2">
            <img src="/logo.png" alt="Vigil" className="w-7 h-7" />
            <span className="text-zinc-50 font-semibold text-[13px] tracking-tight">Vigil</span>
          </div>
        </div>

        <nav className="flex-1 px-2 py-3 space-y-0.5">
          <NavLink to="/accounts" className={navItem}>
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
            </svg>
            Accounts
          </NavLink>
          <NavLink to="/findings" className={navItem}>
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Findings
          </NavLink>
        </nav>

        <div className="px-2 py-3 border-t border-zinc-900">
          <NavLink to="/account" className={navItem}>
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            Account
          </NavLink>
          <button
            onClick={() => { localStorage.removeItem("token"); nav("/login"); }}
            className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded text-[13px] font-medium text-zinc-500 hover:text-zinc-100 hover:bg-zinc-800/50 transition-colors"
          >
            <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <div className="px-8 py-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./index.css";
import Login from "./pages/Login";
import Findings from "./pages/Findings";
import Accounts from "./pages/Accounts";
import AuthCallback from "./pages/AuthCallback";
import Account from "./pages/Account";
import Dashboard from "./pages/Dashboard";
import Settings from "./pages/Settings";
import Layout from "./Layout";

const qc = new QueryClient();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route element={<Layout />}>
            <Route path="/" element={<Navigate to="/findings" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/accounts" element={<Accounts />} />
            <Route path="/account" element={<Account />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);

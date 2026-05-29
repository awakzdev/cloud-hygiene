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
import DetectionCoverage from "./pages/DetectionCoverage";
import Controls from "./pages/Controls";
import GitHubIntegration from "./pages/GitHubIntegration";
import GitHubIntegrationEdit from "./pages/GitHubIntegrationEdit";
import GitLabIntegration from "./pages/GitLabIntegration";
import GitLabIntegrationEdit from "./pages/GitLabIntegrationEdit";
import Integrations from "./pages/Integrations";
import Security from "./pages/Security";
import Timeline from "./pages/Timeline";
import Reference from "./pages/Reference";
import Layout from "./Layout";

const qc = new QueryClient();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/security" element={<Security />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route element={<Layout />}>
            <Route path="/" element={<Navigate to="/findings" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/reference" element={<Reference />} />
            <Route path="/resources" element={<Navigate to="/findings" replace />} />
            <Route path="/accounts" element={<Accounts />} />
            <Route path="/account" element={<Account />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/detection" element={<DetectionCoverage />} />
            <Route path="/controls" element={<Controls />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/integrations/github" element={<GitHubIntegration />} />
            <Route path="/integrations/github/edit" element={<GitHubIntegrationEdit />} />
            <Route path="/integrations/gitlab" element={<GitLabIntegration />} />
            <Route path="/integrations/gitlab/edit" element={<GitLabIntegrationEdit />} />
            <Route path="/timeline" element={<Timeline />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);

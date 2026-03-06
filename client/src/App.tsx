import { Link, Navigate, Route, Routes, useLocation } from "react-router";
import DashboardPage from "./pages/dashboard/DashboardPage";
import DealsListPage from "./pages/deals/DealsListPage";
import DealsKanbanPage from "./pages/deals/DealsKanbanPage";
import DealDetailsPage from "./pages/deals/DealsDetailsPage";
import LeadsListPage from "./pages/leadsList/LeadsListPage";
import SettingsPage from "./pages/settings/SettingsPage";
import LoginPage from "./pages/auth/LoginPage";
import RegisterPage from "./pages/auth/RegisterPage";
import { PrivateRoute, PublicRoute } from "./router/privateRoutes";
import { PUBLIC_URL } from "./config/url.config";
import { ToastContainer } from 'react-toastify';

import ForgotPasswordPage from "./pages/auth/ForgotPasswordPage";
import SideBar from "./layout/SideBar";
import ProfilePage from "./pages/profile/ProfilePage";
import ContactsListPage from "./pages/contacts/ContactsListPage";


export default function App() {
  const location = useLocation();
  const isLoginPage = location.pathname === PUBLIC_URL.login();
  const isRegisterPage = location.pathname === PUBLIC_URL.register();
  const isForgotPasswordPage = location.pathname === PUBLIC_URL.forgot();
  return (

    <div className="min-h-screen flex bg-gray-100">

      {isRegisterPage || isLoginPage || isForgotPasswordPage ? null : <SideBar />}
      <main className="flex-1 p-6 overflow-y-auto">
        <Routes>
          <Route element={<PublicRoute />}>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          </Route>

          <Route element={<PrivateRoute />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/deals" element={<DealsListPage />} />
            <Route path="/deals/kanban" element={<DealsKanbanPage />} />
            <Route path="/deals/:id" element={<DealDetailsPage />} />
            <Route path="/leads" element={<LeadsListPage />} />
            <Route path="/contacts" element={<ContactsListPage />} />
            <Route path="/register" element={<Navigate to="/dashboard" replace />} />
            <Route path="/settings" element={<SettingsPage />} />

            <Route path="*" element={<div>404 Not Found</div>} />
          </Route>

        </Routes>
      </main>
      <ToastContainer />

    </div>
  );
}

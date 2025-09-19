import { Link, Navigate, Route, Routes, useLocation } from "react-router";
import DashboardPage from "./pages/dashboard/DashboardPage";
import DealsListPage from "./pages/deals/DealsListPage";
import DealsKanbanPage from "./pages/deals/DealsKanbanPage";
import DealDetailsPage from "./pages/deals/DealsDetailsPage";
import LeadsListPage from "./pages/leadsList/LeadsListPage";
import ContactsListPage from "./pages/contacts/contactsListPage";
import SettingsPage from "./pages/settings/SettingsPage";
import LoginPage from "./pages/auth/LoginPage";
import RegisterPage from "./pages/auth/RegisterPage";
import { PrivateRoute, PublicRoute } from "./router/privateRoutes";
import { PUBLIC_URL } from "./config/url.config";
import SideBar from "./layout/sideBar";
import { ToastContainer  } from 'react-toastify';
 

export default function App() {
   const location = useLocation();
  const isLoginPage = location.pathname === PUBLIC_URL.login();
  const isRegisterPage = location.pathname === PUBLIC_URL.register();

  return (
    
    <div className="min-h-screen flex bg-gray-100">
     
{isRegisterPage || isLoginPage ? null :   <SideBar/>}
      <main className="flex-1 p-6 overflow-y-auto">
        <Routes>
            <Route element={<PublicRoute/>}>
<Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            </Route>
            
            <Route element={<PrivateRoute />}>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
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

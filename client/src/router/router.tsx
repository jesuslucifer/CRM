import { createBrowserRouter, Navigate } from "react-router"
import { getAccessToken } from "@/service/auth-token.service"


import DashboardPage from "@/pages/dashboard/DashboardPage"
import DealsListPage from "@/pages/deals/DealsListPage"
import DealsKanbanPage from "@/pages/deals/DealsKanbanPage"
import DealDetailsPage from "@/pages/deals/DealsDetailsPage"
import LeadsListPage from "@/pages/leadsList/LeadsListPage"
import ContactsListPage from "@/pages/contacts/ContactsListPage"
import ProfilePage from "@/pages/profile/ProfilePage"
import SettingsPage from "@/pages/settings/SettingsPage"

import LoginPage from "@/pages/auth/LoginPage"
import RegisterPage from "@/pages/auth/RegisterPage"
import ForgotPasswordPage from "@/pages/auth/ForgotPasswordPage"
import AuthLayout from "@/layout/AuthLayout"
import AppLayout from "@/layout/AppLayout"
import { PrivateRoute } from "./privateRoutes"
import CompanyLayout from "@/layout/CompanyLayout"
import CompanyPage from "@/pages/company/CompanyPage"
import CompanyList from "@/pages/company/CompanyListPage"

function requireAuth() {
    const token = getAccessToken()
    if (!token) {
        return <Navigate to="/login" replace />
    }
    return null
}
export const router = createBrowserRouter([
    {
        element: <AuthLayout />,
        children: [
            { path: "/login", element: <LoginPage /> },
            { path: "/register", element: <RegisterPage /> },
            { path: "/forgot-password", element: <ForgotPasswordPage /> },
        ],
    },

    {
        element: <PrivateRoute />,
        children: [
            {
                path: "/",
                element: <AppLayout />,
                children: [

                    { index: true, element: <Navigate to="/dashboard" replace /> },

                    // ===== GLOBAL PAGES =====
                    { path: "dashboard", element: <DashboardPage /> },
                    { path: "profile", element: <ProfilePage /> },
                    { path: "settings", element: <SettingsPage /> },
                    { path: "company-list", element: <CompanyList /> },

                    { path: "*", element: <div>404 Not Found</div> },
                ],

            },
            {
                path: "company/:companyId",
                element: <CompanyLayout />,
                children: [

                    { index: true, element: <Navigate to="dashboard" replace /> },
                    { path: "company", element: <CompanyPage /> },
                    { path: "dashboard", element: <DashboardPage /> },
                    { path: "deals", element: <DealsListPage /> },
                    { path: "deals/kanban", element: <DealsKanbanPage /> },
                    { path: "deals/:id", element: <DealDetailsPage /> },
                    { path: "leads", element: <LeadsListPage /> },
                    { path: "contacts", element: <ContactsListPage /> },

                    { path: "profile", element: <ProfilePage /> },
                    { path: "settings", element: <SettingsPage /> },


                    { path: "*", element: <div>404 Not Found</div> },
                ],

            },
        ],
    },
])
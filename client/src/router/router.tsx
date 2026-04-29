import { createBrowserRouter, Navigate } from "react-router"
import { getAccessToken } from "@/service/auth-token.service"


import DashboardPage from "@/pages/dashboard/DashboardPage"
import DealsListPage from "@/pages/deals/DealsListPage"
import DealsKanbanPage from "@/pages/deals/DealsKanbanPage"
import DealDetailsPage from "@/pages/deals/DealsDetailsPage"
import OrderPage from "@/pages/order/OrderPage"
import ContactsListPage from "@/pages/clients/ClientsPage"
import ProfilePage from "@/pages/profile/ProfilePage"
import SettingsPage from "@/pages/settings/SettingsPage"

import LoginPage from "@/pages/auth/LoginPage"
import RegisterPage from "@/pages/auth/RegisterPage"
import ForgotPasswordPage from "@/pages/auth/ForgotPasswordPage"
import AuthLayout from "@/layout/AuthLayout"
import AppLayout from "@/layout/AppLayout"
import { PrivateRoute } from "./privateRoutes"
import CompanyLayout from "@/layout/company/CompanyLayout"
import CompanyPage from "@/pages/company/CompanyPage"
import CompanyList from "@/pages/company/CompanyListPage"
import CompanyEmployeesPage from "@/pages/employees/CompanyEmployeesPage"
import { PropertyPage } from "@/pages/property/PropertyPage"
import { PropertyDetailsPage } from "@/pages/property/PropertyDetailsPage"
import OrderLayout from "@/layout/order/OrderLayout"
import OrderKanbanPage from "@/pages/order/OrderKanbanPage"

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
                    {
                        path: "crm",

                        children: [
                            { index: true, element: <Navigate to="deals" replace /> },
                            { path: "deals", element: <DealsListPage /> },
                            { path: "kanban", element: <DealsKanbanPage /> },
                            { path: "deals/:id", element: <DealDetailsPage /> },
                            {
                                path: "orders",
                                element: <OrderLayout />,
                                children: [
                                    { index: true, element: <Navigate to="kanban" replace /> },
                                    { path: "list", element: <OrderPage /> },
                                    { path: "kanban", element: <OrderKanbanPage /> },
                                ]
                            },
                            { path: "clients", element: <ContactsListPage /> },

                        ]
                    },
                    {
                        path: "property",
                        element: <PropertyPage />,


                    },
                    { path: "property/:propertyId", element: <PropertyDetailsPage /> },
                    { path: "employees", element: <CompanyEmployeesPage /> },
                    { path: "profile", element: <ProfilePage /> },
                    { path: "settings", element: <SettingsPage /> },


                    { path: "*", element: <div>404 Not Found</div> },
                ],

            },
        ],
    },
])
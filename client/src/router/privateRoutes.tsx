import { Navigate, Outlet } from 'react-router';
import { getAccessToken } from "@/service/auth-token.service";

export const PrivateRoute = () => {
  const token = getAccessToken();
  return token ? <Outlet/> : <Navigate to="/login" />;
};
export const PublicRoute = () => {
  const token = getAccessToken();
  return !token ? <Outlet/> : <Navigate to="/dashboard" />;
}
import { useProfile } from "@/shared/hooks/useProfile";

export default function DashboardPage() {
  const {user, isLoading} = useProfile();

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-2xl shadow p-4">{user?.id}</div>
        <div className="bg-white rounded-2xl shadow p-4">{user?.email}</div>
        <div className="bg-white rounded-2xl shadow p-4">{user?.username}</div>
      </div>
      <div className="bg-white rounded-2xl shadow p-6">Charts / Reports block</div>
    </div>
  );
}

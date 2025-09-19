
export default function SettingsPage() {
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-2xl shadow p-4">General settings</div>
        <div className="bg-white rounded-2xl shadow p-4">Users & Roles</div>
        <div className="bg-white rounded-2xl shadow p-4">Pipelines</div>
      </div>
    </div>
  );
}

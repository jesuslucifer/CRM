export default function DashboardPage() {
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-2xl shadow p-4">Card 1</div>
        <div className="bg-white rounded-2xl shadow p-4">Card 2</div>
        <div className="bg-white rounded-2xl shadow p-4">Card 3</div>
      </div>
      <div className="bg-white rounded-2xl shadow p-6">Charts / Reports block</div>
    </div>
  );
}

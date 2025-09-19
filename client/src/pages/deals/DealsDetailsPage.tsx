export default function DealDetailsPage() {
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Deal #123</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 space-y-4">
          <div className="bg-white rounded-2xl shadow p-4">Overview block</div>
          <div className="bg-white rounded-2xl shadow p-4">Activity timeline</div>
          <div className="bg-white rounded-2xl shadow p-4">Files</div>
        </div>
        <div className="space-y-4">
          <div className="bg-white rounded-2xl shadow p-4">Assignee</div>
          <div className="bg-white rounded-2xl shadow p-4">Company Info</div>
        </div>
      </div>
    </div>
  );
}

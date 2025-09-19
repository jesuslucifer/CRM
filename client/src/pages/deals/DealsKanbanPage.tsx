export default function DealsKanbanPage() {
  const stages = ["New", "In Progress", "Won", "Lost"];
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Deals Kanban</h1>
      <div className="flex gap-4 overflow-x-auto">
        {stages.map((stage) => (
          <div
            key={stage}
            className="w-72 bg-gray-100 rounded-2xl p-4 flex-shrink-0"
          >
            <h2 className="font-semibold mb-3">{stage}</h2>
            <div className="space-y-3">
              {[1, 2].map((id) => (
                <div
                  key={id}
                  className="bg-white rounded-xl shadow p-3 hover:bg-gray-50"
                >
                  <p className="font-medium">Deal {id}</p>
                  <p className="text-sm text-gray-600">$5000 • John Doe</p>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

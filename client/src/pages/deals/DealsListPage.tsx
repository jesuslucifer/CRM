export default function DealsListPage() {
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Deals</h1>
      <div className="bg-white rounded-2xl shadow p-4">
        <div className="flex items-center justify-between mb-4">
          <input
            className="border rounded-lg px-3 py-2 w-64"
            placeholder="Search deals..."
          />
          <button className="bg-blue-600 text-white rounded-lg px-4 py-2">
            + New Deal
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b">
              <th className="py-2 px-3">Title</th>
              <th className="py-2 px-3">Amount</th>
              <th className="py-2 px-3">Stage</th>
              <th className="py-2 px-3">Assignee</th>
              <th className="py-2 px-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3].map((id) => (
              <tr key={id} className="border-b hover:bg-gray-50">
                <td className="py-2 px-3">Deal {id}</td>
                <td className="py-2 px-3">$1000</td>
                <td className="py-2 px-3">New</td>
                <td className="py-2 px-3">John Doe</td>
                <td className="py-2 px-3">
                  <button className="text-blue-600 hover:underline">View</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

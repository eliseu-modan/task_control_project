/**
 *
 * List Tasks
 *
 */

import { Card } from "antd";

import withContext from "../../../contexts/withContexts";
import { useState } from "react";
import { PageEventsProvider } from "../../../contexts";
import { TasksFilter, TasksList } from "../../../components/tasks";
import { useNavigate } from "react-router-dom";

function ListTask({ route, ...props }) {
  const navigate = useNavigate();
  const [filter, setFilter] = useState({
    sortDirection: 0,
    search: "",
  });

  function onEdit(employee) {
    navigate(`/employees/${employee.id}`);
  }

  function onItemsEdit(employee) {
    navigate(`/employees/${employee.id}/items`);
  }

  return (
    <Card className="container">
      <div className="margin-bottom">
        <TasksFilter values={filter} onChange={setFilter} />
      </div>

      <TasksList
        filter={{
          sortDirection: filter.sortDirection,
          search: filter.search,

          page: 1,
        }}
        onEdit={onEdit}
        onItemsEdit={onItemsEdit}
      />
    </Card>
  );
}

export default withContext(PageEventsProvider)(ListTask);

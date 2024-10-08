/**
 *
 * Tasks List Component
 *
 */
import { DeleteOutlined, EditOutlined, InboxOutlined } from "@ant-design/icons";
import { SaveOutlined } from "@ant-design/icons";
import {
  Button,
  Col,
  message,
  Modal,
  Row,
  Table,
  Form,
  Input,
  Checkbox,
} from "antd";
import { Progress } from "antd";
import { useEffect, useState } from "react";
import { useService } from "../../../contexts/service";
import { FormItem } from "../../_commons";
import DashoardPage from "../../../pages/Dashboard";
import React from "react";
import { useSocket } from "../../../contexts/socket-io";
import AlertaComIntervalo from "../../../utils/functions/alerta";
import { useNavigate } from "react-router-dom";
function TasksList({ onEdit, onItemsEdit, filter, ...props }) {
  const [listTask, setListTask] = useState([]);
  const [loading, setLoading] = useState(false);
  const [form] = Form.useForm();
  const { TextArea } = Input;
  const [isEditFormVisible, setIsEditFormVisible] = useState(false);
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10 });
  const [modalVisible, setModalVisible] = useState(false);
  const [originalEmployeeCount, setOriginalEmployeeCount] = useState(0);
  const [ultimoElemento, setUltimoElemento] = useState();
  const [modalVisibleTask, setModalVisibleTask] = useState(false);
  const [selectedTask, setSelectedTask] = useState(null);
  const socket = useSocket();
  const service = useService();
  const navegate = useNavigate();
  const [checkedTasks, setCheckedTasks] = useState([]);



  useEffect(() => {
    getTasks();
  }, [filter, pagination.current, pagination.pageSize, checkedTasks]);

  async function getTasks() {
    setLoading(true);
    try {
      const { data } = await service.get("/tasks/auth/getTasks", {
        params: {
          search: filter.search,
          page: pagination.current,
          pageSize: pagination.pageSize,
          checkedTasks: checkedTasks.join(","),
        },
      });

      setListTask(data.dataTasks);
      setOriginalEmployeeCount(data.countDataTasks);
      const element = data.dataTasks[data.dataTasks.length - 1];
      setUltimoElemento(element.name);
    } finally {
      setLoading(false);
    }
  }
  const calculateProgress = (dateInitial, dateFinally) => {
    const startDate = new Date(dateInitial);
    const endDate = new Date(dateFinally);
    const currentDate = new Date();
    const totalMilliseconds = endDate.getTime() - startDate.getTime();
    const elapsedMilliseconds = currentDate.getTime() - startDate.getTime();
    if (elapsedMilliseconds < 0) return 0;
    if (elapsedMilliseconds >= totalMilliseconds) return 100;
    const percent = ((elapsedMilliseconds / totalMilliseconds) * 100).toFixed(
      0
    );
    return percent;
  };

  function formatDate(dateString) {
    const date = new Date(dateString);
    const day = String(date.getDate()).padStart(2, "0");
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const year = date.getFullYear();
    return `${day}/${month}/${year}`;
  }
  const openModalTask = (task) => {
    setSelectedTask(task);
    setModalVisibleTask(true);
  };
  const closeModalTask = () => {
    setSelectedTask(null);
    setModalVisibleTask(false);
  };
  const handleTaskCheck = (taskId) => {
    const updatedListTask = listTask.map((task) => {
      if (task.id === taskId) {
        task.isCurrent = !task.isCurrent;
      }
      return task;
    });
    const checkedTaskIds = updatedListTask
      .filter((task) => task.isCurrent)
      .map((task) => task.id);
    setListTask(updatedListTask);
    setCheckedTasks(checkedTaskIds);
  };

  const columns = [
    {
      key: "name",
      dataIndex: "isCurrent",
      title: "Tarefa Atual ",
      render: (_, record) => (
        <Checkbox
          checked={record.currentTask}
          onChange={() => handleTaskCheck(record.id)}
        />
      ),
    },

    { key: "name", dataIndex: "name", title: "Nome da Tarefa" },
    { key: "email", dataIndex: "email", title: "Email" },
    {
      key: "Date",
      dataIndex: "Date",
      title: "Data de inicio",
      render: (_, record) => <div>{formatDate(record.dateInitial)}</div>,
    },
    {
      key: "DateTerminio",
      dataIndex: "DateTerminio",
      title: "Data de Término",
      render: (_, record) => <div>{formatDate(record.dateFinally)}</div>,
    },
    {
      key: "progress",
      dataIndex: "progress",
      title: "Status",
      render: (_, record) => (
        <Progress
          style={{ borderRadius: "88px", background: "white" }}
          percent={calculateProgress(record.dateInitial, record.dateFinally)}
          steps={3}
          strokeColor={["#52c41a", "#faad14", "#f5222d"]}
          size={24}
        />
      ),
    },
    {
      key: "subject",
      dataIndex: "subject",
      title: "Tarefa",
      render: (_, record) => (
        <div>
          <Button type="primary" onClick={() => openModalTask(record)}>
            Ver Tarefa
          </Button>
        </div>
      ),
    },

    {
      key: "action",
      title: "Ação",
      align: "center",
      render: (taskSelected) => (
        <Row justify="left" gutter={24}>
          <Col>
            <Button
              icon={<EditOutlined />}
              type="link"
              style={{ position: "relative", top: "0px", left: "0%" }}
              onClick={() => {
                handleEditClick(taskSelected);
              }}
            />
            <Button
              icon={<DeleteOutlined />}
              onClick={() => {
                removeConfirm(taskSelected);
              }}
            />
          </Col>
        </Row>
      ),
    },
    {
      key: "action",
      title: "Concluir",
      align: "center",
      render: (taskSelected) => (
        <Row justify="left" gutter={24}>
          <Col>
            <Button
              onClick={() => {
                confirmConcluided(taskSelected);
              }}
            />
          </Col>
        </Row>
      ),
    },
  ];

  function confirmConcluided(taskSelected) {
    Modal.confirm({
      title: "Concluir Tarefa",
      content: `Deseja realmente Concluir a Tarefa  "${taskSelected.name}?"`,
      okText: "Não",
      cancelText: "Concluir!",
      cancelButtonProps: { danger: true },
      onCancel: () => onConcluided(taskSelected),
    });
  }
  async function onConcluided(taskSelected) {
    try {
      await service.put(`tasks/auth/concluidedTask/${taskSelected.id}`);
      message.success(
        `A Tarefa "${taskSelected.name}" foi Concluida com sucesso!`
      );
      navegate("/Tarefas-Concluidas");
    } catch (error) {
      message.error(
        `Não foi possível Concluir a Tarefa "${taskSelected.name}"`
      );
    }
  }
  function removeConfirm(taskSelected) {
    Modal.confirm({
      title: "Remover Tarefa",
      content: `Deseja realmente Remover a Tarefa  "${taskSelected.name}?"`,
      okText: "Não",
      cancelText: "Remover!",
      cancelButtonProps: { danger: true },
      onCancel: () => onRemove(taskSelected),
    });
  }
  async function onRemove(taskSelected) {
    try {
      await service.delete(`tasks/auth/removeTasks/${taskSelected.id}`);
      getTasks({ page: 1 });
      message.success(
        `A Tarefa "${taskSelected.name}" foi removido com sucesso!`
      );
    } catch (error) {
      message.error(`Não foi possível remover a Tarefa "${taskSelected.name}"`);
    }
  }

  const handleEditClick = (taskSelected) => {
    form.setFieldsValue(taskSelected);
    setModalVisible(true);
  };
  async function onSubmitEdit(values) {
    try {
      setLoading(true);
      const response = await service.patch(
        `/tasks/auth/updateTask/${form.getFieldValue("id")}`,
        values
      );
      getTasks({ page: 1 });
      setIsEditFormVisible(false);
      message.success("Tarefa atualizada com sucesso!");
    } catch (error) {
      message.error("Não foi possível atualizar a Tarefa.");
    } finally {
      setLoading(false);
    }
  }
  const numberTasks = listTask.length;

  return (
    <>
      <div className="editAlert vibrate">
        <AlertaComIntervalo
          mensagem="AVISO !!"
          descricao="VOCÊ PODE TER TAREFAS PERMANENTES !!"
          tipo="warning"
          intervalo={6000}
        />
      </div>
      {listTask.length >= 0 && (
        <DashoardPage
          numberTasks={originalEmployeeCount}
          ultimoElemento={ultimoElemento}
        />
      )}{" "}
      <Table
        columns={columns}
        dataSource={listTask}
        rowKey={(record) => record.id}
        pagination={{
          current: pagination.current,
          pageSize: pagination.pageSize,
          total: listTask.length,
          onChange: (page, pageSize) =>
            setPagination({ current: page, pageSize }),
        }}
        loading={loading}
        scroll={{ x: 670 }}
        style={{
          position: "absolute",
          top: "110%",
          left: "0%",
          width: "100%",
        }}
        {...props}
      />
      <Modal
        visible={modalVisibleTask}
        title="Detalhes da Tarefa :"
        onCancel={closeModalTask}
        footer={null}
      >
        {selectedTask && (
          <div>
            <b>
              <p>{selectedTask.subject}</p>
            </b>
          </div>
        )}
      </Modal>
      <Modal
        title="Editar Tarefa"
        visible={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
      >
        <Form form={form} onFinish={onSubmitEdit} layout="vertical">
          <FormItem
            name="name"
            label="Nome"
            rules={[
              { required: true },
              { type: "name", message: "Nome inválido" },
            ]}
          >
            <Input />
          </FormItem>

          <FormItem
            name="email"
            label="E-mail"
            rules={[
              { required: true },
              { type: "email", message: "E-mail inválido" },
            ]}
          >
            <Input />
          </FormItem>
          <Form.Item
            name="subject"
            label="Digite Sua Tarefa"
            rules={[{ required: true }]}
          >
            <TextArea hidden={4} />
          </Form.Item>
          <Form.Item>
            <Button
              icon={<SaveOutlined />}
              type="primary"
              htmlType="submit"
              loading={loading}
              onClick={(a) => setModalVisible(false)}
            >
              Salvar
            </Button>
            <Button
              id="editButtonCancel"
              icon={<SaveOutlined />}
              type="primary"
              onClick={(a) => setModalVisible(false)}
              style={{ position: "relative", left: "10%" }}
            >
              Cancelar
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

export default TasksList;

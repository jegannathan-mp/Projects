import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import Input from "./Input";
import '../styles/Todo.css'
import { Button,Table,Container,  Input as Inputs } from 'reactstrap'
import backGround from '../assets/wall7.jpg'

const Todo = () => {

  let navigate = useNavigate();

  let sessEmail = sessionStorage.getItem("email")
  let token = sessionStorage.getItem('token')

  const [res, setRes] = useState([]);
  const [isEditing, setIsEditing] = useState(false);
  const [todo, setTodo] = useState("");
  const [editId, setEditId] = useState(null);

  useEffect(() => {
    getMethod();
  }, []);


  const getMethod = async () => {
    // debugger
    try {
      let response = await axios.get(`http://localhost:3100/todoget/${sessEmail}`, {
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }
      });
      setRes(response.data.data);
    } catch (error) {
      console.log("Error fetching", error);
    }
  };

  const deleteMethod = async (id) => {
    try {
      let response = await axios.delete(`http://localhost:3100/tododlt/${id}`,
        { headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` } }
      );
      getMethod();
    } catch (error) {
      console.log("Error deleting", error);
    }
  };

  const handleUpdateClick = (item) => {
    setIsEditing(true);
    setTodo(item.Todo);
    setEditId(item._id);
  };

  const handleCancelClick = () => {
    setIsEditing(false);
  };

  const handleInputChange = (e) => {
    setTodo(e.target.value);
  };

  const handleSaveClick = async () => {
    try {
      // debugger
      let response = await axios.put(
        `http://localhost:3100/todoupd/${editId}`,
        { Todo: todo },
        { headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` } }
      );
      setIsEditing(false);
      setEditId(null);
      getMethod();
    } catch (error) {
      console.log("Error Updating", error);
    }
  };


  return (
    <>
      <div className="todo_first">
        <img src={backGround} className="todo_img" alt="jk" />
        <Input getMethod={getMethod} />
        <Container className='todo_contain_ori'>
        <div className="todo_contain">
          <div className="todo_head">
            <h1 className="todo_h1">Todo List</h1>
            <span className="todo_h1_span">{sessEmail}</span>
          </div>

          <Table className="todo_table" hover responsive bordered striped >
            <thead className="todo_thead">
              <tr className="todo_thtr">
                <th>Todo</th>
                <th>Update</th>
                <th>Delete</th>
              </tr>
            </thead>
            <tbody  className="todo_tbody">
              {res.map((item, key) => (
                <tr key={key}>
                  {isEditing && editId === item._id ? (
                    <td><Inputs className="todo_input" type="text" onChange={handleInputChange} value={todo} /></td>
                  ) : (
                    <td>{item.Todo}</td>
                  )}

                  {isEditing && editId === item._id ? (
                    <>
                      <td className="todo_btn todo_double">
                        <Button className="todo_save" onClick={handleSaveClick}>Save</Button>
                        <Button className="todo_cancel" onClick={handleCancelClick}>Cancel</Button>
                      </td>
                    </>
                  ) : (
                    <td className="todo_btn">
                      <Button className="todo_update" onClick={() => handleUpdateClick(item)}>Update</Button>
                    </td>
                  )}
                  <td className="todo_btn">
                    <Button className="todo_delete" onClick={() => deleteMethod(item._id)}>Delete</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
          </Container>
      </div>
    </>
  );
};

export default Todo;

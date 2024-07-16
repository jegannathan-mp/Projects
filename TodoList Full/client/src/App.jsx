import React, { createContext, useState } from 'react'
import Todo from './components/Todo'
import Input from './components/Input'
import { Routes,Route } from 'react-router-dom'
import SignIn from './components/SignIn'
import SignUp from './components/SignUp'
import Forgot from './components/Forgot'
import UpdatePass from './components/UpdatePass'
import './App.css'


export const ContextValue = createContext();
     
const App = () => {

  const [contEmail, setContEmail] = useState('');
  const [contId, setContId] = useState(null);

  return <>
    <ContextValue.Provider value={{contId,setContId,contEmail,setContEmail}}>
    <Routes>
      <Route path="/todo" element={<Todo/>} />
      <Route path="/signin" element={<SignIn/>} />
      <Route path="/" element={<SignUp/>} />
      <Route path='/forgot' element={<Forgot/>}/>
      <Route path='/updatepass' element={<UpdatePass/>} />
    </Routes>
    </ContextValue.Provider>
    </>
}

export default App
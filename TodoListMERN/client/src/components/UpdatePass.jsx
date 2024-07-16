import React, { useContext, useState } from 'react'
import { ContextValue } from '../App'
import axios from 'axios'
import { ToastContainer, toast, Zoom } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css';
import { useNavigate } from 'react-router-dom';
import { Button,  Form, FormGroup,  Label, Input } from 'reactstrap'
import '../styles/UpdatePass.css'
import backGround from '../assets/wall9.jpg'

const UpdatePass = () => {

    const navigate = useNavigate()

    const { contId, setContId } = useContext(ContextValue)
    const [input, setInput] = useState('')
    const [input1, setInput1] = useState('')



    console.log(contId)

    const updatePassword = async (e) => {
        e.preventDefault()

        try {
            if (input == input1) {
                let response = await axios.put(`http://localhost:3100/bcryptput/${contId}`, { password: input })
                console.log(response.data.statusCode)
                toast.success('🦄 Password Updated', {
                    position: "top-center",
                    autoClose: 3000,
                    hideProgressBar: false,
                    closeOnClick: true,
                    pauseOnHover: true,
                    draggable: true,
                    progress: undefined,
                    theme: "dark",
                    transition: Zoom,
                });
                setTimeout(() => navigate('/signin'), 1500);
            }

            if (input != input1) {
                toast.error('🦄 Password doesn\'t Match', {
                    position: "top-center",
                    autoClose: 3500,
                    hideProgressBar: false,
                    closeOnClick: true,
                    pauseOnHover: true,
                    draggable: true,
                    progress: undefined,
                    theme: "dark",
                    transition: Zoom,
                });
                setInput('')
                setInput1('')
            }

        } catch (error) {
            console.log(error)
        }
    }

    const backToSignIn = () => {
        navigate('/signin')
    }

    return (
        <div className='update_contain'>
            <ToastContainer />
            <img src={backGround} className='update_img' alt="" />
            <div className='update_divhead'>
                <h2 className='update'>Identify Your Account</h2>
                <Form>
                    <FormGroup className='update_1'>
                        <h4>These Email matched your search</h4>
                    </FormGroup>
                    <FormGroup className='update_2'>
                        <Label htmlFor="newpassword" className='update_label' >New Password</Label>
                        <Input type="password" id='newpassword' className='update_input'  onChange={(e) => setInput(e.target.value)} placeholder='New Password : ' />
                    </FormGroup>
                    <FormGroup className='update_3'>
                        <Label htmlFor="confirmpassword" className='update_label' >Confirm Password</Label>
                        <Input type="password" id='confirmpassword' className='update_input'  onChange={(e) => setInput1(e.target.value)} placeholder='Confirm Password' />
                    </FormGroup>
                    <FormGroup className='update_4'>
                        <Button type='submit' onClick={updatePassword} className='update_update' >Update</Button>
                        <Button onClick={backToSignIn} className='update_signin' >Back To Sign In</Button>
                    </FormGroup>
                </Form>
            </div>
        </div>
    )
}

export default UpdatePass
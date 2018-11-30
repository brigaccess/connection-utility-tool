import React, {Component} from 'react';
import {Link} from "react-router-dom";


class Alert extends Component {
    constructor(props) {
        super(props);

        this.getClassNames = () => {
            let selfClassNames = "custom-alert rounded";//  p-3 mb-5 bg-white rounded
            let customClassNames = this.props.className;

            return selfClassNames + " " + customClassNames;
        }
    }

    render() {
        return (
            <div className={this.getClassNames()} onClick={this.props.onClick}>

                <img src="./images/error.svg"
                     width="25" height="25"
                     className=""
                     alt=""/>
                <div className="">
                    <p><b>{this.props.title}</b></p>
                    <p>{this.props.text}</p>
                </div>

                {/*<button type="button" className="close" aria-label="Close">
                    <span aria-hidden="true"/>
                </button>*/}

            </div>
        );
    }
}

export default Alert;


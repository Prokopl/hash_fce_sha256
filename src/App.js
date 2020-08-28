import React from 'react';
import './App.css';

import MySha256 from './sha256.js';
import sha256 from 'js-sha256';

class App extends React.Component {

  constructor() {
    super()
    this.state = {
      text: '',
      hash: '',
      ref1: '',
    }
    this.startHash = this.startHash.bind(this)
  }

  startHash(event) {
    this.setState({text: event.target.value})
    const hashed = MySha256.hashIt(event.target.value)
    const ref1 = sha256(event.target.value)
    this.setState({hash: hashed, ref1: ref1})
    if (event.target.value === "") {
      this.setState({
        text: '',
        hash: '',
        ref1: ''
      })
    }
  }

  render() {
    return (
      <div>
        <h1>SHA-256</h1>
        <div class="content">
          <div class="input-field">
            <h2>Vstupní text</h2>
            <textarea onChange={this.startHash}></textarea>
          </div>
          <div class="output-field">
            <h2>Hash</h2>
            <textarea value={this.state.hash} readOnly></textarea>
          </div>
          <div class="output-field">
            <h2>Referenční hash</h2>
            <textarea value={this.state.ref1} readOnly></textarea>
          </div>
        </div>
      </div>
    )
  }
}

export default App;
